/******************************************************************************
 *
 * Program: Swap space plugin for Nagios
 * License: GPL
 *
 * License Information:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Copyright (c) 2000 Karl DeBisschop (kdebisschop@users.sourceforge.net)
 *
 * $Id$
 *
 *****************************************************************************/

#include "common.h"
#include "popen.h"
#include "utils.h"

const char *progname = "check_swap";
const char *revision = "$Revision$";
const char *copyright = "2000-2003";
const char *email = "nagiosplug-devel@lists.sourceforge.net";

int check_swap (int usp, long unsigned int free_swap);
int process_arguments (int argc, char **argv);
int validate_arguments (void);
void print_usage (void);
void print_help (void);

int warn_percent = 0;
int crit_percent = 0;
unsigned long long warn_size = 0;
unsigned long long crit_size = 0;
int verbose;
int allswaps;

int
main (int argc, char **argv)
{
	int percent_used, percent;
	unsigned long long total_swap = 0, used_swap = 0, free_swap = 0;
	unsigned long long dsktotal, dskused, dskfree, tmp;
	int result = STATE_OK;
	char input_buffer[MAX_INPUT_BUFFER];
	char *perf;
#ifdef HAVE_PROC_MEMINFO
	FILE *fp;
#else
# ifdef HAVE_SWAP
	int conv_factor;		/* Convert to MBs */
	char *temp_buffer;
	char *swap_command;
	char *swap_format;
# endif
#endif
	char str[32];
	char *status;

	setlocale (LC_ALL, "");
	bindtextdomain (PACKAGE, LOCALEDIR);
	textdomain (PACKAGE);

	status = strdup ("");
	perf = strdup ("");

	if (process_arguments (argc, argv) != OK)
		usage (_("Invalid command arguments supplied\n"));

#ifdef HAVE_PROC_MEMINFO
	fp = fopen (PROC_MEMINFO, "r");
	while (fgets (input_buffer, MAX_INPUT_BUFFER - 1, fp)) {
		if (sscanf (input_buffer, "%*[S]%*[w]%*[a]%*[p]%*[:] %llu %llu %llu", &dsktotal, &dskused, &dskfree) == 3) {
			dsktotal = dsktotal / 1048576;
			dskused = dskused / 1048576;
			dskfree = dskfree / 1048576;
			total_swap += dsktotal;
			used_swap += dskused;
			free_swap += dskfree;
			if (allswaps) {
				if (dsktotal == 0)
					percent=100.0;
				else
					percent = 100 * (((double) dskused) / ((double) dsktotal));
				result = max_state (result, check_swap (percent, dskfree));
				if (verbose)
					asprintf (&status, "%s [%llu (%d%%)]", status, dskfree, 100 - percent);
			}
		}
		else if (sscanf (input_buffer, "%*[S]%*[w]%*[a]%*[p]%[TotalFre]%*[:] %llu %*[k]%*[B]", str, &tmp)) {
			if (strcmp ("Total", str) == 0) {
				dsktotal = tmp / 1024;
			}
			else if (strcmp ("Free", str) == 0) {
				dskfree = tmp / 1024;
			}
		}
	}
	fclose(fp);
	dskused = dsktotal - dskfree;
	total_swap = dsktotal;
	used_swap = dskused;
	free_swap = dskfree;
#else
# ifdef HAVE_SWAP
	asprintf(&swap_command, "%s", SWAP_COMMAND);
	asprintf(&swap_format, "%s", SWAP_FORMAT);
	conv_factor = SWAP_CONVERSION;

/* These override the command used if a summary (and thus ! allswaps) is required */
/* The summary flag returns more accurate information about swap usage on these OSes */
#  ifdef _AIX
	if (!allswaps) {
		asprintf(&swap_command, "%s", "/usr/sbin/lsps -s");
		asprintf(&swap_format, "%s", "%d%*s %d");
		conv_factor = 1;
	}
#  else
#   ifdef sun
	if (!allswaps) {
		asprintf(&swap_command, "%s", "/usr/sbin/swap -s");
		asprintf(&swap_format, "%s", "%*s %*dk %*s %*s + %*dk %*s = %dk %*s %dk %*s");
		conv_factor = 2048;
	}
#   endif
#  endif

	if (verbose >= 2)
		printf (_("Command: %s\n"), swap_command);
	if (verbose >= 3)
		printf (_("Format: %s\n"), swap_format);

	child_process = spopen (swap_command);
	if (child_process == NULL) {
		printf (_("Could not open pipe: %s\n"), swap_command);
		return STATE_UNKNOWN;
	}

	child_stderr = fdopen (child_stderr_array[fileno (child_process)], "r");
	if (child_stderr == NULL)
		printf (_("Could not open stderr for %s\n"), swap_command);

	sprintf (str, "%s", "");
	/* read 1st line */
	fgets (input_buffer, MAX_INPUT_BUFFER - 1, child_process);
	if (strcmp (swap_format, "") == 0) {
		temp_buffer = strtok (input_buffer, " \n");
		while (temp_buffer) {
			if (strstr (temp_buffer, "blocks"))
				sprintf (str, "%s %s", str, "%f");
			else if (strstr (temp_buffer, "dskfree"))
				sprintf (str, "%s %s", str, "%f");
			else
				sprintf (str, "%s %s", str, "%*s");
			temp_buffer = strtok (NULL, " \n");
		}
	}

/* If different swap command is used for summary switch, need to read format differently */
#  ifdef _AIX
	if (!allswaps) {
		fgets(input_buffer, MAX_INPUT_BUFFER - 1, child_process);	/* Ignore first line */
		sscanf (input_buffer, swap_format, &total_swap, &used_swap);
		free_swap = total_swap * (100 - used_swap) /100;
		used_swap = total_swap - free_swap;
		if (verbose >= 3)
			printf (_("total=%d, used=%d, free=%d\n"), total_swap, used_swap, free_swap);
	} else {
#  else
#   ifdef sun
	if (!allswaps) {
		sscanf (input_buffer, swap_format, &used_swap, &free_swap);
		used_swap = used_swap / 1024;
		free_swap = free_swap / 1024;
		total_swap = used_swap + free_swap;
	} else {
#   endif
#  endif
		while (fgets (input_buffer, MAX_INPUT_BUFFER - 1, child_process)) {
			sscanf (input_buffer, swap_format, &dsktotal, &dskfree);

			dsktotal = dsktotal / conv_factor;
			/* AIX lists percent used, so this converts to dskfree in MBs */
#  ifdef _AIX
			dskfree = dsktotal * (100 - dskfree) / 100;
#  else
			dskfree = dskfree / conv_factor;
#  endif
			if (verbose >= 3)
				printf (_("total=%d, free=%d\n"), dsktotal, dskfree);

			dskused = dsktotal - dskfree;
			total_swap += dsktotal;
			used_swap += dskused;
			free_swap += dskfree;
			if (allswaps) {
				percent = 100 * (((double) dskused) / ((double) dsktotal));
				result = max_state (result, check_swap (percent, dskfree));
				if (verbose)
					asprintf (&status, "%s [%llu (%d%%)]", status, dskfree, 100 - percent);
			}
		}
#  ifdef _AIX
	}
#  else
#   ifdef sun
	}
#   endif
#  endif

	/* If we get anything on STDERR, at least set warning */
	while (fgets (input_buffer, MAX_INPUT_BUFFER - 1, child_stderr))
		result = max_state (result, STATE_WARNING);

	/* close stderr */
	(void) fclose (child_stderr);

	/* close the pipe */
	if (spclose (child_process))
		result = max_state (result, STATE_WARNING);
# endif /* HAVE_SWAP */
#endif /* HAVE_PROC_MEMINFO */

	percent_used = 100 * ((double) used_swap) / ((double) total_swap);
	result = max_state (result, check_swap (percent_used, free_swap));
	asprintf (&status, _(" %d%% free (%llu MB out of %llu MB)%s"),
						(100 - percent_used), free_swap, total_swap, status);

	asprintf (&perf, "%s", perfdata ("swap", (long) free_swap, "MB",
		TRUE, (long) max (warn_size/1024, warn_percent/100.0*total_swap),
		TRUE, (long) max (crit_size/1024, crit_percent/100.0*total_swap),
		TRUE, 0,
		TRUE, (long) total_swap));
	printf ("SWAP %s:%s |%s\n", state_text (result), status, perf);
	return result;
}




int
check_swap (int usp, long unsigned int free_swap)
{
	int result = STATE_UNKNOWN;
	free_swap = free_swap * 1024;		/* Convert back to bytes as warn and crit specified in bytes */
	if (usp >= 0 && crit_percent != 0 && usp >= (100.0 - crit_percent))
		result = STATE_CRITICAL;
	else if (crit_size > 0 && free_swap <= crit_size)
		result = STATE_CRITICAL;
	else if (usp >= 0 && warn_percent != 0 && usp >= (100.0 - warn_percent))
		result = STATE_WARNING;
	else if (warn_size > 0 && free_swap <= warn_size)
		result = STATE_WARNING;
	else if (usp >= 0.0)
		result = STATE_OK;
	return result;
}


/* process command-line arguments */
int
process_arguments (int argc, char **argv)
{
	int c = 0;  /* option character */

	int option = 0;
	static struct option longopts[] = {
		{"warning", required_argument, 0, 'w'},
		{"critical", required_argument, 0, 'c'},
		{"allswaps", no_argument, 0, 'a'},
		{"verbose", no_argument, 0, 'v'},
		{"version", no_argument, 0, 'V'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	if (argc < 2)
		return ERROR;

	while (1) {
		c = getopt_long (argc, argv, "+?Vvhac:w:", longopts, &option);

		if (c == -1 || c == EOF)
			break;

		switch (c) {
		case 'w':									/* warning size threshold */
			if (is_intnonneg (optarg)) {
				warn_size = atoi (optarg);
				break;
			}
			else if (strstr (optarg, ",") &&
							 strstr (optarg, "%") &&
							 sscanf (optarg, "%llu,%d%%", &warn_size, &warn_percent) == 2) {
				break;
			}
			else if (strstr (optarg, "%") &&
							 sscanf (optarg, "%d%%", &warn_percent) == 1) {
				break;
			}
			else {
				usage (_("Warning threshold must be integer or percentage!\n"));
			}
		case 'c':									/* critical size threshold */
			if (is_intnonneg (optarg)) {
				crit_size = atoi (optarg);
				break;
			}
			else if (strstr (optarg, ",") &&
							 strstr (optarg, "%") &&
							 sscanf (optarg, "%llu,%d%%", &crit_size, &crit_percent) == 2) {
				break;
			}
			else if (strstr (optarg, "%") &&
							 sscanf (optarg, "%d%%", &crit_percent) == 1) {
				break;
			}
			else {
				usage (_("Critical threshold must be integer or percentage!\n"));
			}
		case 'a':									/* all swap */
			allswaps = TRUE;
			break;
		case 'v':									/* verbose */
			verbose++;
			break;
		case 'V':									/* version */
			print_revision (progname, revision);
			exit (STATE_OK);
		case 'h':									/* help */
			print_help ();
			exit (STATE_OK);
		case '?':									/* error */
			usage (_("Invalid argument\n"));
		}
	}

	c = optind;
	if (c == argc)
		return validate_arguments ();
	if (warn_percent == 0 && is_intnonneg (argv[c]))
		warn_percent = atoi (argv[c++]);

	if (c == argc)
		return validate_arguments ();
	if (crit_percent == 0 && is_intnonneg (argv[c]))
		crit_percent = atoi (argv[c++]);

	if (c == argc)
		return validate_arguments ();
	if (warn_size == 0 && is_intnonneg (argv[c]))
		warn_size = atoi (argv[c++]);

	if (c == argc)
		return validate_arguments ();
	if (crit_size == 0 && is_intnonneg (argv[c]))
		crit_size = atoi (argv[c++]);

	return validate_arguments ();
}





int
validate_arguments (void)
{
	if (warn_percent == 0 && crit_percent == 0 && warn_size == 0
			&& crit_size == 0) {
		return ERROR;
	}
	else if (warn_percent < crit_percent) {
		usage
			(_("Warning percentage should be more than critical percentage\n"));
	}
	else if (warn_size < crit_size) {
		usage
			(_("Warning free space should be more than critical free space\n"));
	}
	return OK;
}






void
print_help (void)
{
	print_revision (progname, revision);

	printf (_(COPYRIGHT), copyright, email);

	printf (_("Check swap space on local server.\n\n"));

	print_usage ();

	printf (_(UT_HELP_VRSN));

	printf (_("\n\
 -w, --warning=INTEGER\n\
   Exit with WARNING status if less than INTEGER bytes of swap space are free\n\
 -w, --warning=PERCENT%%\n\
   Exit with WARNING status if less than PERCENT of swap space is free\n\
 -c, --critical=INTEGER\n\
   Exit with CRITICAL status if less than INTEGER bytes of swap space are free\n\
 -c, --critical=PERCENT%%\n\
   Exit with CRITCAL status if less than PERCENT of swap space is free\n\
 -a, --allswaps\n\
    Conduct comparisons for all swap partitions, one by one\n\
 -v, --verbose\n\
    Verbose output. Up to 3 levels\n"));

	printf (_("\n\
On Solaris, if -a specified, uses swap -l, otherwise uses swap -s.\n\
Will be discrepencies because swap -s counts allocated swap and includes\n\
real memory\n"));
	printf (_("\n\
On AIX, if -a is specified, uses lsps -a, otherwise uses lsps -s.\n"));

	printf (_(UT_SUPPORT));
}




void
print_usage (void)
{
	printf (_("Usage:\n\
 %s [-av] -w <percent_free>%% -c <percent_free>%%\n\
 %s [-av] -w <bytes_free> -c <bytes_free>\n\
 %s (-h | --help) for detailed help\n\
 %s (-V | --version) for version information\n"),
	        progname, progname, progname, progname);
}
