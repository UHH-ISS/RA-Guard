# https://github.com/p4lang/p4c/
FROM p4lang/behavioral-model:latest

# ARG P4C_COMMIT=c1cf3c4a5dcad6f9ee846fda96e65e18c0863f77
ARG P4C_COMMIT=ecba24ad591e719268860f66202530830d2a914e
# Default to using 2 make jobs, which is a good default for CI. If you're
# building locally or you know there are more cores available, you may want to
# override this.
ARG MAKEFLAGS=-j2

# Select the type of image we're building. Use `build` for a normal build, which
# is optimized for image size. Use `test` if this image will be used for
# testing; in this case, the source code and build-only dependencies will not be
# removed from the image.
ARG IMAGE_TYPE=build

# Whether to do a unified build.
ARG ENABLE_UNIFIED_COMPILATION=ON

# Whether to enable translation validation
ARG VALIDATION=OFF

# Delegate the build to tools/travis-build.
RUN apt-get update && apt-get install -yq git
RUN git clone https://github.com/p4lang/p4c /p4c/
WORKDIR /p4c/
RUN git checkout ${P4C_COMMIT}
RUN git submodule update --init --recursive
RUN chmod u+x tools/travis-build && tools/travis-build

