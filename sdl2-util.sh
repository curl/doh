#!/usr/bin/env bash
#set -x
install_SDL2() {
	curl --silent -L https://www.libsdl.org/release/SDL2-2.0.10.tar.gz | tar xz -k
	cd SDL2-2.0.10
	./configure
	make
	sudo make install
	cd ../
}
check_SDL2_installed() {
       echo -e "#include<SDL2/SDL.h>\nint main(){}" | gcc -lSDL2 -xc - && echo "yes" || echo "no"
}
if [ "$1" = "--check" ]; then
	check_SDL2_installed
elif [ "$1" = "--install" ]; then
	if [ "$(check_SDL2_installed)" = "yes" ]; then
		echo "SDL2 already installed" >&2
		# cleanup
		rm a.out
	else
		echo "SDL2 is not installed, installing..." >&2
	       install_SDL2
	fi
fi
