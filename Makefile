NAME = Compressor

COMPILER = clang
FLAGS = -Wall -Wextra -Werror
SRC_C = main.c compress.c
ASSAMBLER = nasm
ASSAMBLER_FLAGS = -f bin

OBJC = $(SRC_C:.c=.o)

BONUS_OBJ = $(BONUS_SRC_C:_bonus.c=_bonus.o)

all: $(NAME)

$(NAME): $(OBJC)
	$(COMPILER) $(FLAGS) $(OBJC) -o $(NAME)
	$(ASSAMBLER) $(ASSAMBLER_FLAGS) stub64.s -o stub64.bin

%.o: %.c compressor.h
	$(COMPILER) $(FLAGS) -c $< -o $@

clean:
	rm -rf $(OBJC) $(BOBJC)

fclean: clean
	rm -rf $(NAME) stub64.bin

re: fclean all