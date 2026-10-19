#include <stdbool.h>
#include "ft_nmap.h"

static int	set_scans(const char *text, t_options *options)
{
	char	*copy;
	char	*token;
	char	*saveptr;

	copy = strdup(text);
	if (copy == NULL)
		return (1);
	token = strtok_r(copy, ",", &saveptr);
	if (token == NULL)
	{
		free(copy);
		return (1);
	}
	while (token != NULL)
	{
		if (strcmp(token, "SYN") == 0)
			options->scan_syn = 1;
		else if (strcmp(token, "NULL") == 0)
			options->scan_null = 1;
		else if (strcmp(token, "ACK") == 0)
			options->scan_ack = 1;
		else if (strcmp(token, "FIN") == 0)
			options->scan_fin = 1;
		else if (strcmp(token, "XMAS") == 0)
			options->scan_xmas = 1;
		else if (strcmp(token, "UDP") == 0)
			options->scan_udp = 1;
		else
		{
			fprintf(stderr, "Erreur : type de scan inconnu : %s\n", token);
			free(copy);
			return (1);
		}
		token = strtok_r(NULL, ",", &saveptr);
	}
	free(copy);
	return (0);
}

static int	parse_speedup(const char *text, int *value)
{
	char	*endptr;
	long	number;

	errno = 0;
	number = strtol(text, &endptr, 10);
	if (text[0] == '\0' || *endptr != '\0' || errno == ERANGE)
		return (1);
	if (number < 0 || number > 250)
		return (1);
	*value = (int)number;
	return (0);
}

static int	require_value(int argc, char **argv, int index)
{
	if (index + 1 >= argc || argv[index + 1][0] == '\0')
	{
		fprintf(stderr, "Erreur : valeur manquante après %s\n", argv[index]);
		return (1);
	}
	return (0);
}

static int	parse_port_number(const char *text, long *value)
{
	char	*endptr;
	long	number;

	if (text[0] < '0' || text[0] > '9')
		return (1);
	errno = 0;
	number = strtol(text, &endptr, 10);
	if (*endptr != '\0' || errno == ERANGE)
		return (1);
	if (number < 1 || number > 65535)
		return (1);
	*value = number;
	return (0);
}

static int	mark_range(const char *token, bool *seen, int *count)
{
	char	*dash;
	char	*copy;
	long	start;
	long	end;
	int		ret;

	copy = strdup(token);
	if (copy == NULL)
		return (1);
	dash = strchr(copy, '-');
	if (dash != NULL)
		*dash++ = '\0';
	ret = parse_port_number(copy, &start);
	end = start;
	if (ret == 0 && dash != NULL)
		ret = parse_port_number(dash, &end);
	free(copy);
	if (ret != 0)
		return (1);
	if (start > end)
		return (2);
	while (start <= end)
	{
		if (!seen[start])
		{
			seen[start] = true;
			(*count)++;
		}
		start++;
	}
	return (0);
}

static int	parse_ports(const char *text, t_options *options)
{
	static bool	seen[65536];
	char		*copy;
	char		*token;
	char		*saveptr;
	int			count;
	int			ret;
	int			i;
	int			j;

	if (text == NULL)
		text = "1-1024";
	memset(seen, 0, sizeof(seen));
	count = 0;
	copy = strdup(text);
	if (copy == NULL)
		return (1);
	token = strtok_r(copy, ",", &saveptr);
	if (token == NULL)
	{
		fprintf(stderr, "Erreur : liste de ports vide.\n");
		free(copy);
		return (1);
	}
	while (token != NULL)
	{
		ret = mark_range(token, seen, &count);
		if (ret != 0)
		{
			if (ret == 2)
				fprintf(stderr, "Erreur : plage de ports inversée : %s\n", token);
			else
				fprintf(stderr, "Erreur : port invalide (1-65535) : %s\n", token);
			free(copy);
			return (1);
		}
		if (count > 1024)
		{
			fprintf(stderr, "Erreur : plus de 1024 ports demandés.\n");
			free(copy);
			return (1);
		}
		token = strtok_r(NULL, ",", &saveptr);
	}
	free(copy);
	options->ports = malloc(count * sizeof(*options->ports));
	if (options->ports == NULL)
		return (1);
	i = 0;
	j = 1;
	while (j <= 65535)
	{
		if (seen[j])
			options->ports[i++] = j;
		j++;
	}
	options->port_count = count;
	return (0);
}

void	free_targets(t_options *options)
{
	size_t	i;

	i = 0;
	while (i < options->target_count)
		free(options->targets[i++].name);
	free(options->targets);
	options->targets = NULL;
	options->target_count = 0;
}

static char	*trim_line(char *line)
{
	char	*end;

	while (isspace((unsigned char)*line))
		line++;
	end = line + strlen(line);
	while (end > line && isspace((unsigned char)end[-1]))
		end--;
	*end = '\0';
	return (line);
}

static int	add_target(const char *target, t_options *options)
{
	t_target	*grown;
	char		*copy;

	copy = strdup(target);
	if (copy == NULL)
		return (1);
	grown = realloc(options->targets,
			(options->target_count + 1) * sizeof(*options->targets));
	if (grown == NULL)
	{
		free(copy);
		return (1);
	}
	options->targets = grown;
	memset(&grown[options->target_count], 0, sizeof(*grown));
	grown[options->target_count++].name = copy;
	return (0);
}

/* Une cible par ligne ; les blancs autour sont ignorés, les lignes vides aussi. */
static int	read_targets_file(const char *path, t_options *options)
{
	FILE	*stream;
	char	*line;
	size_t	size;
	char	*target;

	stream = fopen(path, "r");
	if (stream == NULL)
	{
		fprintf(stderr, "Erreur : impossible d'ouvrir %s : %s\n",
			path, strerror(errno));
		return (1);
	}
	line = NULL;
	size = 0;
	while (getline(&line, &size, stream) != -1)
	{
		target = trim_line(line);
		if (target[0] != '\0' && add_target(target, options) != 0)
		{
			fprintf(stderr, "Erreur : mémoire insuffisante.\n");
			free(line);
			fclose(stream);
			free_targets(options);
			return (1);
		}
	}
	free(line);
	if (ferror(stream))
	{
		fprintf(stderr, "Erreur : lecture de %s impossible : %s\n",
			path, strerror(errno));
		fclose(stream);
		free_targets(options);
		return (1);
	}
	fclose(stream);
	if (options->target_count == 0)
	{
		fprintf(stderr, "Erreur : aucune cible dans %s\n", path);
		return (1);
	}
	return (0);
}

int	parse_args(int argc, char **argv, t_options *options)
{
	int	i;
	int	scan_option_seen;

	if (options == NULL)
		return (1);
	i = 1;
	scan_option_seen = 0;
	while (i < argc)
	{
		if (strcmp(argv[i], "--help") == 0)
		{
			print_help();
			exit(0);
		}
		else if (strcmp(argv[i], "--ip") == 0)
		{
			if (require_value(argc, argv, i))
				return (1);
			if (options->ip != NULL || options->file != NULL)
			{
				fprintf(stderr, "Erreur : utilise --ip ou --file, pas les deux.\n");
				return (1);
			}
			options->ip = argv[++i];
		}
		else if (strcmp(argv[i], "--file") == 0)
		{
			if (require_value(argc, argv, i))
				return (1);
			if (options->ip != NULL || options->file != NULL)
			{
				fprintf(stderr, "Erreur : utilise --ip ou --file, pas les deux.\n");
				return (1);
			}
			options->file = argv[++i];
		}
		else if (strcmp(argv[i], "--ports") == 0
			|| strcmp(argv[i], "--port") == 0)
		{
			if (require_value(argc, argv, i))
				return (1);
			if (options->ports != NULL)
			{
				fprintf(stderr, "Erreur : option ports donnée plusieurs fois.\n");
				return (1);
			}
			if (parse_ports(argv[++i], options) != 0)
				return (1);
		}
		else if (strcmp(argv[i], "--speedup") == 0)
		{
			if (require_value(argc, argv, i))
				return (1);
			if (parse_speedup(argv[++i], &options->thread_count) != 0)
			{
				fprintf(stderr, "Erreur : --speedup doit être un entier entre 0 et 250.\n");
				return (1);
			}
		}
		else if (strcmp(argv[i], "--scan") == 0)
		{
			if (require_value(argc, argv, i))
				return (1);
			if (scan_option_seen)
			{
				fprintf(stderr, "Erreur : option --scan donnée plusieurs fois.\n");
				return (1);
			}
			scan_option_seen = 1;
			if (set_scans(argv[++i], options) != 0)
				return (1);
		}
		else
		{
			fprintf(stderr, "Erreur : option inconnue : %s\n", argv[i]);
			return (1);
		}
		i++;
	}
	if (options->ip == NULL && options->file == NULL)
	{
		fprintf(stderr, "Erreur : indique une cible avec --ip ou --file.\n");
		return (1);
	}
	if (options->file != NULL
		&& read_targets_file(options->file, options) != 0)
		return (1);
	if (options->ip != NULL && add_target(options->ip, options) != 0)
	{
		fprintf(stderr, "Erreur : mémoire insuffisante.\n");
		return (1);
	}
	if (options->ports == NULL && parse_ports(NULL, options) != 0)
		return (1);
	if (!scan_option_seen)
	{
		options->scan_syn = 1;
		options->scan_null = 1;
		options->scan_ack = 1;
		options->scan_fin = 1;
		options->scan_xmas = 1;
		options->scan_udp = 1;
	}
	return (0);
}