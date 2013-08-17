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

int p_error(int code);
void usage(char *myname);
void p_help(char *myname);
void check_status_arg(char *arg);
void check_limit_arg(int uwarn, int lwarn, int ucrit, int lcrit);
int check_final_result(int uwarn, int lwarn, int ucrit, int lcrit, int numproc);

typedef unsigned short bool;  
bool v_debug;
bool use_warn;
bool use_crit;

void usage(char *myname) 
{
	fprintf(stderr, "Usage: %s [-C command] [-a arguments] [-s status] [-S status] [-p pid] [-u username] [-w warning_limit_upper:warning_limit_lower] [-c critical_limit_upper:critical_limit_lower] [-h]\n", myname);
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
check_final_result(int uwarn, int lwarn, int ucrit, int lcrit, int numproc)
{
	int errcode;
	if (use_warn && (numproc < uwarn || numproc > lwarn))
		errcode = 0;
	if (use_warn && use_crit && ((numproc >= uwarn && numproc < ucrit) || (numproc <= lwarn && numproc > lcrit)))
		errcode = 1;
	if (use_crit && (numproc >= ucrit || numproc <= lcrit))
		errcode = 2;
	if (!use_warn && !use_crit)
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
	}
	if (!vcnt)
	{
		fprintf(stderr, "Status argument is not valid. It can be only - \"[F | R | D | T | Z | W | L]\". Please, read the help\n");
		exit(2);
	}
}

void 
check_limit_arg(int uwarn, int lwarn, int ucrit, int lcrit)
{
	if (uwarn < lwarn)
	{
		fprintf(stderr, "Limit argument for Warning check status is not correct. Upper value (%d) < Lover value (%d)\n", uwarn, lwarn);
		exit(2);
	}
	if (ucrit < lcrit)
	{
		fprintf(stderr, "Limit argument for Critical check status is not correct. Upper value (%d) < Lover value (%d)\n", ucrit, lcrit);
		exit(2);
	}
	if ( use_warn && use_crit && uwarn > ucrit)
	{
		fprintf(stderr, "Limit argument for check status is not correct. Upper value for warning (%d) > Upper value for critical (%d)\n", uwarn, ucrit);
		exit(2);
	}
	if (use_warn && use_crit && lwarn < lcrit)
	{
		fprintf(stderr, "Limit argument for check status is not correct. Lower value for warning (%d) < Lover value for critical (%d)\n", lwarn, lcrit);
		exit(2);
	}
}

void
p_help(char *myname) 
{
	printf("Usage: %s [-C command] [-a arguments] [-s status] [-S status] [-p pid] [-u username] [-w warning_limit_upper:warning_limit_lower] [-c critical_limit_upper:critical_limit_lower] [-d] [-h]\n\n", myname);
	printf("-C command   -- processes command, which meaning for find\n");
	printf("-a arguments -- processes argument, which meaning for find\n");
	printf("-s status    -- processes with status. Can be only:\n"); 
	printf("                \"F\" - Process being created by fork\n");
	printf("                \"R\" - Currently runnable\n");
	printf("                \"D\" - Sleeping on an address\n");
	printf("                \"T\" - Process debugging or suspension\n");
	printf("                \"Z\" - Awaiting collection by parent (zombie)\n");
	printf("                \"W\" - Waiting for interrupt\n");
	printf("                \"L\" - Blocked on a lock\n");
	printf("-S status    -- processes without status.\n"); 
	printf("-p pid       -- find process with pid\n");
	printf("-p user      -- find process which ran from user\n");
	printf("-w warning   -- warning limit for check: [upper:lower]\n");
	printf("-c critical  -- critical limit for check: [upper:lower]\n");
	printf("-d           -- debug output\n");
	printf("-h           -- print this help\n");
	exit(0);
}

int
main (int argc, char **argv)
{
    struct kinfo_proc* kp;
    kvm_t *kd;
    int cntp;
    int ppid;
    char *errbuf;
    char **pargs;
    char *sep = ":";
    char *res;
    // parse opt
    int bflag, ch, fd;
    int print_all;
    int i;
    // parametr's check
    unsigned int m_warn;
    char *m_swarn;
    unsigned int m_uwarn;
    unsigned int m_lwarn;
    unsigned int m_crit;
    char *m_scrit;
    unsigned int m_ucrit;
    unsigned int m_lcrit;
    unsigned int m_pid;
    char m_status[MAX_PSTATUS_LEN];
    char m_user[MAX_USERNAME_LEN];
    char m_command[MAX_PARGS_LEN];
    char m_arguments[MAX_PARGS_LEN];
    //status var
    unsigned int s_pnum;
    char *s_pname;
    pid_t s_mypid;
    char *s_myname;
    int errcode;

    use_warn = use_crit = v_debug = FALSE; //debug print = false

    s_mypid = getpid();
    s_myname = argv[0];

    bzero(m_status, MAX_PSTATUS_LEN);
    bzero(m_user, MAX_USERNAME_LEN);
    bzero(m_command, MAX_PARGS_LEN);
    bzero(m_arguments, MAX_PARGS_LEN);

    m_warn = m_uwarn = m_lwarn = m_crit = m_ucrit = m_lcrit = m_pid = print_all = 0;
    s_pnum = errcode = 0;

    print_all=argc;

    bflag = 0;
    while ((ch = getopt(argc, argv, "w:c:s:p:u:C:a:hd")) != -1) {
	    switch (ch) {
	    case 'w':
		    m_warn = atoi(optarg);
		    for (m_swarn = strtok(optarg, sep), i=0; m_swarn; (m_swarn = strtok(NULL, sep)) && i++)
		    {
			    if (!i)
				    m_uwarn = atoi(m_swarn);
			    if (i==1)
				    m_lwarn = atoi(m_swarn);
				    
		    }
		    if (i==0 || i>1)
		    {
			    fprintf(stderr, "Limit argument for Warning check status isn't correct. Num: %d. Please, see help\n", i);
			    exit(2);
		    }
		    use_warn = TRUE;
		    break;
	    case 'c':
		    m_crit = atoi(optarg);
		    for (m_scrit = strtok(optarg, sep), i=0; m_scrit; (m_scrit = strtok(NULL, sep)) && i++)
		    {
			    if (!i)
				    m_ucrit = atoi(m_scrit);
			    if (i==1)
				    m_lcrit = atoi(m_scrit);
				    
		    }
		    if (i==0 || i>1)
		    {
			    fprintf(stderr, "Limit argument for Critical check status isn't correct. Num: %d. Please, see help\n", i);
			    exit(2);
		    }
		    use_crit = TRUE;
		    break;
	    case 'p':
		    m_pid = atoi(optarg);
		    break;
	    case 's':
		    if (strlen(optarg) <= MAX_PSTATUS_LEN)
		    {
			    check_status_arg(optarg);
			    strcpy(m_status, optarg);
		    }
		    else
			    p_error(E_BUFF);
		    break;
	    case 'u':
		    if (strlen(optarg) <= MAX_USERNAME_LEN)
			    strcpy(m_user, optarg);
		    else
			    p_error(E_BUFF);
		    break;
	    case 'C':
		    if (strlen(optarg) <= MAX_PARGS_LEN)
			    strcpy(m_command, optarg);
		    else
			    p_error(E_BUFF);
		    break;
	    case 'a':
		    if (strlen(optarg) <= MAX_PARGS_LEN)
			    strcpy(m_arguments, optarg);
		    else
			    p_error(E_BUFF);
		    break;
	    case 'h':
		    p_help(s_myname);
		    break;
	    case 'd':	
		    v_debug = TRUE;
		    break;
	    default:
		    usage(s_myname);
	    }
    }
    argc -= optind;
    argv += optind;

    check_limit_arg(m_uwarn, m_lwarn, m_ucrit, m_lcrit);

    kd = kvm_open(NULL, "/dev/null", NULL, O_RDONLY, errbuf);
    kp = kvm_getprocs(kd, KERN_PROC_PROC, 0, &cntp);

    if (print_all<2)
    {
	printf("%s: %d processes\n", OK, cntp);
	kvm_close(kd);
	exit(0);
    }

    if (v_debug)
	printf("Mypid: %d\n", s_mypid);
    for(;cntp>0;cntp-- && kp++)
    {
	int stcnt = 0;	
	ppid = kp->ki_pid;    
	pargs = kvm_getargv(kd, kp, 0);
	if (s_mypid == ppid)
	{
		if (v_debug)
		    printf("Mypid: continue...\n");
		continue;
	}
	if (pargs)
	    s_pname = strtok(basename(pargs[0]), sep);
	if (!s_pname && strlen(m_command)>0)
	    continue;	
	if (strlen(m_command)>0)
	{
	    if (!strcmp(m_command, s_pname)) 
	    {
		    s_pnum++;
		    if (v_debug)
			printf("Add: m_command: %s pid: %d\n", s_pname, ppid);
	    }
	    else
		    continue;
	}
	if (strlen(m_arguments) && pargs)
	{
	    int argcnt = 0;	
	    for (i=1; pargs[i]; i++)
	    {
		res = strstr(pargs[i], m_arguments);    
		if (res)
		{
		    argcnt++;
		    break;
		}
	    }
	    if (argcnt && !strlen(m_command))
		    s_pnum++;
	    if (!argcnt && strlen(m_command)>0 && s_pnum)
		    s_pnum--;
	}
	
	for (i=0; m_status[i]; i++)
	{
	    if (!s_pnum)
		    continue;
	    if (strlen(m_command)>0 || strlen(m_arguments)>0)
	    {
		switch (kp->ki_stat)
		{
		    case SSTOP: /* Process debugging or suspension. */
			if (m_status[i] == 'T') stcnt++;
			break;
		    case SSLEEP: /* Sleeping on an address. */
			if (m_status[i] == 'D') stcnt++;
			break;
		    case SIDL: /* Process being created by fork */
			if (m_status[i] == 'F') stcnt++;
			break;
		    case SWAIT: /* Waiting for interrupt. */
			if (m_status[i] == 'W') stcnt++;
			break;
		    case SLOCK: /* Blocked on a lock. */
			if (m_status[i] == 'L') stcnt++;
			break;
		    case SZOMB: /* Awaiting collection by parent. */
			if (m_status[i] == 'Z') stcnt++;
			break;
		    case SRUN: /* Currently runnable. */
			if (m_status[i] == 'R') stcnt++;
			break;
		}
	    }
	    else
	    {
		switch (kp->ki_stat)
		{
		    case SSTOP: /* Process debugging or suspension. */
			if (m_status[i] == 'T') stcnt++; s_pnum++;
			break;
		    case SSLEEP: /* Sleeping on an address. */
			if (m_status[i] == 'D') stcnt++; s_pnum++;
			break;
		    case SIDL: /* Process being created by fork */
			if (m_status[i] == 'F') stcnt++; s_pnum++;
			break;
		    case SWAIT: /* Waiting for interrupt. */
			if (m_status[i] == 'W') stcnt++; s_pnum++;
			break;
		    case SLOCK: /* Blocked on a lock. */
			if (m_status[i] == 'L') stcnt++; s_pnum++;
			break;
		    case SZOMB: /* Awaiting collection by parent. */
			if (m_status[i] == 'Z') stcnt++; s_pnum++;
			break;
		    case SRUN: /* Currently runnable. */
			if (m_status[i] == 'R') stcnt++; s_pnum++;
			break;
		}
	    }
	    //printf("%d:  %d:%d\n", kp->ki_pid, kp->ki_stat, kistate->m_status[0]);
	}
	if (!stcnt && m_status[0] && s_pnum)
		s_pnum--;
	s_pname = NULL;
    }

    errcode = check_final_result(m_uwarn, m_lwarn, m_ucrit, m_lcrit, s_pnum);
	    
    switch (errcode) {
	    case 0:
		if (strlen(m_command) && strlen(m_status) && strlen(m_arguments)) printf("%s: %d processes with parametrs name: \"%s\" args: \"%s\" status: \"%s\"\n", OK, s_pnum, m_command, m_arguments, m_status);
		else printf("%s: %d processes\n", OK, s_pnum);
		break;
	    case 1:	
		if (strlen(m_command) && strlen(m_status) && strlen(m_arguments)) printf("%s: %d processes with parametrs name: \"%s\" args: \"%s\" status: \"%s\"\n", WARNING, s_pnum, m_command, m_arguments, m_status);
		else printf("%s: %d processes\n", WARNING, s_pnum);
		break;
	    case 2:	
		if (strlen(m_command) && strlen(m_status) && strlen(m_arguments)) printf("%s: %d processes with parametrs name: \"%s\" args: \"%s\" status: \"%s\"\n", CRITICAL, s_pnum, m_command, m_arguments, m_status);
		else printf("%s: %d processes\n", CRITICAL, s_pnum);
		break;
    }
    kvm_close(kd);
    exit(errcode);
}
