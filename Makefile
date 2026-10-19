NAME = ft_nmap

CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c11 -D_DEFAULT_SOURCE -Iinclude
LDLIBS = -lpcap -lpthread

SRC = src/main.c \
      src/args.c \
      src/ports.c \
      src/output.c \
      src/parsing.c \
      src/resolve.c

OBJ = $(SRC:.c=.o)

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(OBJ) $(LDLIBS) -o $(NAME)

%.o: %.c include/ft_nmap.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re