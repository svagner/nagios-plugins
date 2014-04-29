/*****************************************************************************
* 
* Nagios check_procs_bsd plugin
* 
* License: BSD
* Copyright (c) 2013 Stanislav Putrya
* email: vagner@bsdway.ru
* 
* Description:
* 
* This file contains the check_procs_bsd plugin
* using kvm(3) interface
*
* URL: https://github.com/svagner/nagios-plugins
* compile with options: clang -lkvm check_procs_bsd.c -o check_procs_bsd
* 
*****************************************************************************/

#include <fcntl.h>
#include <kvm.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/proc.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

#define MAX_PSTATUS_LEN 7
#define MAX_TSTATUS_LEN 7
#define MAX_USERNAME_LEN 100
#define MAX_PARGS_LEN 1000

//error's codes
#define E_BUFF	1

#define TRUE	1
#define FALSE	0

//states
#define OK	    "PROCS OK"
#define CRITICAL    "PROCS CRITICAL"
#define WARNING	    "PROCS WARNING"

#ifndef DEBUG
#define DEBUG	    0
#endif

#ifndef __FreeBSD_version
#error
#endif

// 
#define FCOMMAND    0x0000000001
#define FARGS	    0x0000000010
#define FSTATUS	    0x0000000100
#define FWSTATUS    0x0000001000
#define FPID	    0x0000010000
#define FUSER	    0x0000100000
#define FWARNING    0x0001000000
#define FCRITICAL   0x0010000000
#define TSTATUS	    0x0100000000
#define TWSTATUS    0x1000000000

#define SGOOD       0x01
#define SBAD        0x10

#define WMESGLEN    8

typedef unsigned short bool;  
typedef struct {
	char *pname;
	char **pargs;
	int pstate;
	int pid;
	char *uid;
	char *tstate;
} t_procinfo;

typedef struct {
    unsigned int pid;
    unsigned int cnt;
    unsigned short state;
} pid_s;

typedef struct {
#if (__FreeBSD_version==901504)	
	char pcmd[TDNAMLEN+1];
#elif (__FreeBSD_version<901504)	
	char pcmd[MAX_PARGS_LEN+1];
#endif	
	char pargs[MAX_PARGS_LEN];
	char pstate[MAX_PSTATUS_LEN];
	char pwstate[MAX_PSTATUS_LEN];
    char tstate[MAX_TSTATUS_LEN];
    char twstate[MAX_TSTATUS_LEN];
	int ppid;
	char puid[LOGNAMELEN+1];
	int warn_upper_limit;
	int warn_lover_limit;
	int crit_lover_limit;
	int crit_upper_limit;
	struct timeval ki_start;
} t_filters;

bool v_debug;

int p_error(int code);
void usage(char *myname);
void p_help(char *myname);
void check_status_arg(char *arg);
void check_limit_arg(unsigned int filters, t_filters *f);
int check_final_result(unsigned int filters, t_filters *f, int numproc);
uint64_t check_proc_filters(uint64_t filters, t_procinfo *pinfo, t_filters *f);
int check_proc_status(int status, char *filter);
int check_thread_status(char *status, char *filter);
int result_print(int errcode, unsigned int filter, t_filters *f, int s_pnum);

void usage(char *myname) 
{
	fprintf(stderr, "Usage: %s [-C command] [-a arguments] [-s status] [-S status] [-p pid] [-u username] [-w warning_limit_upper:warning_limit_lower] [-c critical_limit_upper:critical_limit_lower] [-t] [-d] [-h]\n", myname);
	exit(2);
}

int
p_error(int ecode)
{
	switch (ecode) {
	case E_BUFF:	
	    fprintf(stderr, "Error: buffer overflow!\n");
	    break;
	default:  
	    return 0;
	}
	exit(2);    
}

int 
check_final_result(unsigned int filters, t_filters *f, int numproc)
{
	int errcode;
	if ((filters & FWARNING) && (numproc < f->warn_upper_limit || numproc > f->warn_lover_limit))
		errcode = 0;
	if ((filters & FWARNING) && (filters & FCRITICAL) && ((numproc >= f->warn_upper_limit && numproc < f->crit_upper_limit) || (numproc <= f->warn_lover_limit && numproc > f->crit_lover_limit)))
		errcode = 1;
	if ((filters & FCRITICAL) && (numproc >= f->crit_upper_limit || numproc <= f->crit_lover_limit))
		errcode = 2;
	if (!(filters & FWARNING) && !(filters & FCRITICAL))
		errcode = 0;
	if (v_debug)
	    fprintf(stderr, "Error code: %d\n", errcode);
	return errcode;
}

void 
check_status_arg(char *arg)
{
	int i, ii;
	int vcnt, vlistcnt;
	vcnt = vlistcnt = 0;
	char valid[] = "FRDTZWL";
	vlistcnt = sizeof(valid)/sizeof(*valid);

	for (i=0; arg[i]; i++)
	{
		for (ii=0;ii<vlistcnt;ii++)
			if (arg[i] == valid[ii])
				vcnt++;
		if (!vcnt)
			goto exit;
		vcnt = 0;
	}
	return;
exit:
	fprintf(stderr, "Status argument is not valid. It can be only - \"[F | R | D | T | Z | W | L]\". Please, read the help\n");
	exit(2);
}

void 
check_limit_arg(unsigned int filters, t_filters *f)
{
	if (f->warn_upper_limit < f->warn_lover_limit)
	{
		fprintf(stderr, "Limit argument for Warning check status is not correct. Upper value (%d) < Lover value (%d)\n", f->warn_upper_limit, f->warn_lover_limit);
		exit(2);
	}
	if (f->crit_upper_limit < f->crit_lover_limit)
	{
		fprintf(stderr, "Limit argument for Critical check status is not correct. Upper value (%d) < Lover value (%d)\n", f->crit_upper_limit, f->crit_lover_limit);
		exit(2);
	}
	if ((filters & FWARNING) && (filters & FCRITICAL) && f->warn_upper_limit > f->crit_upper_limit)
	{
		fprintf(stderr, "Limit argument for check status is not correct. Upper value for warning (%d) > Upper value for critical (%d)\n", f->warn_upper_limit, f->crit_upper_limit);
		exit(2);
	}
	if ((filters & FWARNING) && (filters & FCRITICAL) && f->warn_lover_limit < f->crit_lover_limit)
	{
		fprintf(stderr, "Limit argument for check status is not correct. Lower value for warning (%d) < Lover value for critical (%d)\n", f->warn_lover_limit, f->crit_lover_limit);
		exit(2);
	}
}

void
p_help(char *myname) 
{
	printf("Usage: %s [-C command] [-a arguments] [-s status] [-S status] [-W state] [-T state] [-p pid] [-u username] [-w warning_limit_upper:warning_limit_lower] [-c critical_limit_upper:critical_limit_lower] [-t] [-d] [-h]\n\n", myname);
	printf("-C command      -- processes command, which meaning for find\n");
	printf("-a arguments    -- processes argument, which meaning for find\n");
	printf("-s status       -- processes with status. Can be only:\n"); 
	printf("                    \"F\" - Process being created by fork\n");
	printf("                    \"R\" - Currently runnable\n");
	printf("                    \"D\" - Sleeping on an address\n");
	printf("                    \"T\" - Process debugging or suspension\n");
	printf("                    \"Z\" - Awaiting collection by parent (zombie)\n");
	printf("                    \"W\" - Waiting for interrupt\n");
	printf("                    \"L\" - Blocked on a lock\n");
	printf("-W state        -- thread with state. Can be only:\n");
	printf("                    \"l\" - uwrlck\n");
	printf("                    \"w\" - uwait\n");
	printf("-T state        -- thread without state. Can be only:\n");
	printf("-S status       -- processes without status.\n"); 
	printf("-p pid          -- find process with pid\n");
	printf("-p user         -- find process which ran from user\n");
	printf("-w warning      -- warning limit for check: [upper:lower]\n");
	printf("-c critical     -- critical limit for check: [upper:lower]\n");
	printf("-t              -- consider check threads\n");
	printf("-d              -- debug output\n");
	printf("-h              -- print this help\n");
	exit(0);
}

static int
compare_pidnums(const void *first, const void *second) {
    if (((pid_s *)first)->pid > ((pid_s *)second)->pid) {
        return 1;
    } else if (((pid_s *)first)->pid < ((pid_s *)second)->pid) {
        return -1;
    } else {
        return 0;
    }
}

int
main (int argc, char **argv)
{
    struct kinfo_proc* kp, *kpt;
    kvm_t *kd;
    int cntp, cntpt;
    char *errbuf;
    char *sep = ":";
    char *res;
    // parse opt
    int bflag, ch, fd;
    int print_all;
    int i;
    // parametr's check
    t_filters Filters;
    unsigned int m_warn;
    char *m_swarn;
    unsigned int m_uwarn;
    unsigned int m_lwarn;
    unsigned int m_crit;
    char *m_scrit;
    uint64_t filter = 0;
    //status var
    unsigned int s_pnum;
    pid_t s_mypid;
    char *s_myname;
    // for threads check
    pid_s *pidlist;
    bool threads_check = FALSE;
    int errcode;

    v_debug = FALSE; //debug print = false

    s_mypid = getpid();
    s_myname = argv[0];

    bzero(&Filters, sizeof(t_filters));

    m_warn = m_crit = print_all = 0;
    s_pnum = errcode = 0;

    print_all=argc;

    bflag = 0;
    while ((ch = getopt(argc, argv, "w:c:s:S:p:u:C:T:W:a:hdt")) != -1) {
	    switch (ch) {
	    case 'w':
		    m_warn = atoi(optarg);
		    filter = filter ^ FWARNING;
		    for (m_swarn = strtok(optarg, sep), i=0; m_swarn; (m_swarn = strtok(NULL, sep)) && i++)
		    {
			    if (!i)
				    Filters.warn_upper_limit = atoi(m_swarn);
			    if (i==1)
				    Filters.warn_lover_limit = atoi(m_swarn);
				    
		    }
		    if (i==0 || i>1)
		    {
			    fprintf(stderr, "Limit argument for Warning check status isn't correct. Num: %d. Please, see help\n", i);
			    exit(2);
		    }
		    break;
	    case 'c':
		    m_crit = atoi(optarg);
		    filter = filter ^ FCRITICAL;
		    for (m_scrit = strtok(optarg, sep), i=0; m_scrit; (m_scrit = strtok(NULL, sep)) && i++)
		    {
			    if (!i)
				    Filters.crit_upper_limit = atoi(m_scrit);
			    if (i==1)
				    Filters.crit_lover_limit = atoi(m_scrit);
		    }
		    if (i==0 || i>1)
		    {
			    fprintf(stderr, "Limit argument for Critical check status isn't correct. Num: %d. Please, see help\n", i);
			    exit(2);
		    }
		    break;
	    case 'p':
		    filter = filter ^ FPID;
		    Filters.ppid = atoi(optarg);
		    break;
	    case 's':
		    if (strlen(optarg) <= MAX_PSTATUS_LEN)
		    {
			    check_status_arg(optarg);
			    filter = filter ^ FSTATUS;
			    strcpy(Filters.pstate, optarg);
		    }
		    else
			    p_error(E_BUFF);
		    break;
	    case 'S':
		    if (strlen(optarg) <= MAX_PSTATUS_LEN)
		    {
			    check_status_arg(optarg);
			    filter = filter ^ FWSTATUS;
			    strcpy(Filters.pwstate, optarg);
		    }
		    else
			    p_error(E_BUFF);
		    break;
	    case 'W':
		    if (strlen(optarg) <= MAX_TSTATUS_LEN)
		    {
			    //check_status_arg(optarg);
                filter = filter ^ TSTATUS;
			    strcpy(Filters.tstate, optarg);
		    }
		    else
			    p_error(E_BUFF);
		    break;
	    case 'T':
		    if (strlen(optarg) <= MAX_TSTATUS_LEN)
		    {
			    //check_status_arg(optarg);
                filter = filter ^ TWSTATUS;
			    strcpy(Filters.twstate, optarg);
		    }
		    else
			    p_error(E_BUFF);
		    break;
	    case 'u':
		    if (strlen(optarg) <= MAX_USERNAME_LEN)
		    {
			    filter = filter ^ FUSER;
			    strcpy(Filters.puid, optarg);
		    }
		    else
			    p_error(E_BUFF);
		    break;
	    case 'C':
		    if (strlen(optarg) <= MAX_PARGS_LEN)
		    {
			    filter = filter ^ FCOMMAND;
			    strcpy(Filters.pcmd, optarg);
		    }
		    else
			    p_error(E_BUFF);
		    break;
	    case 'a':
		    if (strlen(optarg) <= MAX_PARGS_LEN)
		    {
			    filter = filter ^ FARGS;
			    strcpy(Filters.pargs, optarg);
		    }
		    else
			    p_error(E_BUFF);
		    break;
	    case 'h':
		    p_help(s_myname);
		    break;
	    case 'd':	
		    v_debug = TRUE;
		    break;
	    case 't':	
		    threads_check = TRUE;
		    break;
	    default:
		    usage(s_myname);
	    }
    }
    argc -= optind;
    argv += optind;

    if (v_debug)
	    printf("%p\n", filter);

    check_limit_arg(filter, &Filters);

    kd = kvm_open(NULL, "/dev/null", NULL, O_RDONLY, errbuf);
    kp = kvm_getprocs(kd, KERN_PROC_PROC, 0, &cntp);
    if (threads_check) {
        kpt = kvm_getprocs(kd, KERN_PROC_PROC, 0, &cntpt);
        kp = kvm_getprocs(kd, KERN_PROC_PROC|KERN_PROC_INC_THREAD, 0, &cntp);
        //pidlist = calloc(cntp, sizeof(pid_s));
        pidlist = malloc(sizeof(pid_s)*cntpt);
        memset(pidlist, 0, cntpt);
    } else {
        kp = kvm_getprocs(kd, KERN_PROC_PROC, 0, &cntp);
    }

    if (print_all<2) {
	    printf("%s: %d processes\n", OK, cntp);
	    kvm_close(kd);
	    exit(0);
    }

    for(;cntp>0;cntp-- && kp++) {
	    int stcnt = 0;	
	    t_procinfo proc_info;

	    bzero(&proc_info, sizeof(t_procinfo));
	
	    proc_info.pid = kp->ki_pid;
	    if (s_mypid == proc_info.pid) {
		    if (v_debug)
		        printf("Mypid: continue...\n");
		    continue;
	    }

	    if (kp->ki_args)
	        proc_info.pargs = kvm_getargv(kd, kp, 0);
	    proc_info.pstate = kp->ki_stat;
	    proc_info.tstate = kp->ki_wmesg;
        //printf("%d - %d (%s) [%x]\n", kp->ki_pid, kp->ki_kiflag & KI_LOCKBLOCK, kp->ki_wmesg, kp->ki_wchan);
	    proc_info.uid = kp->ki_login;

	    if (proc_info.pargs)
	        proc_info.pname = strtok(basename(proc_info.pargs[0]), sep);	
	    else
#if (__FreeBSD_version==901504)	
	        proc_info.pname = kp->ki_tdname;
#elif (__FreeBSD_version<901504)	
	        proc_info.pname = kp->ki_ocomm;
#endif	

        pid_s *mypid;
        pid_s search_key;
	    if (!check_proc_filters(filter, &proc_info, &Filters)) {
            if (threads_check) {
                search_key.pid = kp->ki_pid;
                if ((mypid = bsearch(&search_key, pidlist, cntpt, sizeof(pid_s), compare_pidnums))!=NULL) {
                    if (mypid->state & SBAD)
                        continue;
                    mypid->cnt++;
                } else  {
                    search_key.pid = 0;
                    mypid = bsearch(&search_key, pidlist, cntpt, sizeof(pid_s), compare_pidnums);
                    mypid->pid = kp->ki_pid;
                    mypid->cnt = 1;
                    mypid->state = SGOOD;
                    qsort(pidlist, cntpt, sizeof(pid_s), compare_pidnums);
		            s_pnum++;
                }
            } else {
		        s_pnum++;
            }
		    Filters.ki_start.tv_sec = kp->ki_start.tv_sec;
		    Filters.ki_start.tv_usec = kp->ki_start.tv_usec;
	    } else if (threads_check) {
            search_key.pid = kp->ki_pid;
            if ((mypid = bsearch(&search_key, pidlist, cntpt, sizeof(pid_s), compare_pidnums))!=NULL && mypid->state & SGOOD) { 
                mypid->state = SBAD;
                s_pnum--;
            } else {
                search_key.pid = 0;
                mypid = bsearch(&search_key, pidlist, cntpt, sizeof(pid_s), compare_pidnums);
                mypid->pid = kp->ki_pid;
                mypid->cnt = 1;
                mypid->state = SBAD;
                qsort(pidlist, cntpt, sizeof(pid_s), compare_pidnums);
            }
        }
    }

    errcode = check_final_result(filter, &Filters, s_pnum);
	    
    result_print(errcode, filter, &Filters, s_pnum);

    kvm_close(kd);
    exit(errcode);
}

uint64_t 
check_proc_filters(uint64_t filters, t_procinfo *pinfo, t_filters *f)
{
	uint64_t errcode;
	char *res;
	int i, cnt; 
	uint64_t result = 0x0000000000;
	i = cnt = 0;
	res = NULL;

	if (filters & FCOMMAND && !strcmp(f->pcmd, pinfo->pname)) 
		result = result ^ FCOMMAND;
	if (filters & FARGS && pinfo->pargs) 
	{
	    for (i=1; pinfo->pargs[i]; i++)
	    {
		res = strstr(pinfo->pargs[i], f->pargs);    
		if (res)
		{
		    cnt++;
		    break;
		}
	    }
	    if (cnt)
		result = result ^ FARGS;    
	}
	if (filters & FSTATUS && check_proc_status(pinfo->pstate, f->pstate))
		result = result ^ FSTATUS;

	if (filters & FWSTATUS && !check_proc_status(pinfo->pstate, f->pwstate))
		result = result ^ FWSTATUS;

	if (filters & TSTATUS && check_thread_status(pinfo->tstate, f->tstate))
		result = result ^ TSTATUS;

	if (filters & TWSTATUS && !check_thread_status(pinfo->tstate, f->twstate))
		result = result ^ TWSTATUS;

	if (filters & FCRITICAL)
		result = result ^ FCRITICAL;

	if (filters & FWARNING)
		result = result ^ FWARNING;

	if (filters & FPID && (pinfo->pid == f->ppid))
		result = result ^ FPID;

	if (v_debug)
	    printf("result:%p filters:%p\n", result, filters);
	errcode = filters ^ result;
	if (v_debug)
	    printf("Error code from check_proc_filters: %p\n", errcode);
	return errcode;
};

int
check_thread_status(char *status, char *filter)
{
	int i;
	int errcode = 0;
	for (i=0; filter[i]; i++) {
        if ((filter[i] == 'l' && !strncmp(status, "uwrlck", 6)) || (filter[i] == 'w' && !strncmp(status, "uwait", 5))) 
            errcode++;
    }
    return errcode;
}

int
check_proc_status(int status, char *filter)
{
	int i;
	int errcode = 0;

	for (i=0; filter[i]; i++)
	{
	    switch (status)
	    {
		case SSTOP: /* Process debugging or suspension. */
			if (filter[i] == 'T') errcode++;
			break;
		case SSLEEP: /* Sleeping on an address. */
			if (filter[i] == 'D') errcode++;
			break;
		case SIDL: /* Process being created by fork */
			if (filter[i] == 'F') errcode++;
			break;
		case SWAIT: /* Waiting for interrupt. */
			if (filter[i] == 'W') errcode++;
			break;
		case SLOCK: /* Blocked on a lock. */
			if (filter[i] == 'L') errcode++;
			break;
		case SZOMB: /* Awaiting collection by parent. */
			if (filter[i] == 'Z') errcode++;
			break;
		case SRUN: /* Currently runnable. */
			if (filter[i] == 'R') errcode++;
			break;
	    }
	}
	return errcode;
}

int 
result_print(int errcode, unsigned int filter, t_filters *f, int s_pnum)
{
	struct tm *tp;
	time_t then;
	size_t buflen = 1000;
	char *runtimebuf;
	static int use_ampm = -1;
	time_t now;

	time(&now);
	runtimebuf = malloc(buflen);

	then = f->ki_start.tv_sec;
	tp = localtime(&then);

	if (now - f->ki_start.tv_sec < 24 * 3600) {
		(void)strftime(runtimebuf, buflen, use_ampm ? "%l:%M%p" : "%k:%M  ", tp);
	} else if (now - f->ki_start.tv_sec < 7 * 86400)
	{
		(void)strftime(runtimebuf, buflen,use_ampm ? "%a%I%p" : "%a%H  ", tp);
	}
	else
		(void)strftime(runtimebuf, buflen, "%e%b%y", tp);

	switch (errcode) {
	    case 0:
		printf("%s:", OK);
		break;
	    case 1:	
		printf("%s:", WARNING);
		break;
	    case 2:	
		printf("%s:", CRITICAL);
		break;
	}

	printf(" %d processes", s_pnum);

	if (filter != 0)
		printf(" with parametrs");
	if (filter & FCOMMAND)
		printf(" name: \'%s\'", f->pcmd);
	if (filter & FARGS)
		printf(" args_like: \'%s\'", f->pargs);
	if (filter & FPID)
		printf(" pid: \'%s\'", f->ppid);
	if (filter & FSTATUS)
		printf(" status: \'%s\'", f->pstate);
	if (filter & FWSTATUS)
		printf(" not_status: \'%s\'", f->pwstate);
	if (s_pnum > 0)
	    printf(". Last procs is run at: %s", runtimebuf);
	else
	    printf(".\n");
	free(runtimebuf);
	return 0;
}
