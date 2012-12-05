if [ -d build ]; then
    rm -rf build
fi

if [ ! -d build ]; then
    mkdir build
fi

cd build

if [ ! -e 'CMakeCache.txt' ] || [ ! -d 'CMakeFiles' ]; then
    cmake ..
fi

make

