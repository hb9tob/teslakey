cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# La version est fixee explicitement, et non deduite par 'git describe'.
# Sans le mot-cle VERSION, ESP-IDF appelle git_describe() : dans un depot
# sans aucun commit (ou hors depot), 'git rev-parse HEAD' echoue et la
# configuration CMake s'arrete sur GetGitRevisionDescription.cmake.
# Le projet doit pouvoir se compiler independamment de l'etat du depot.
project(teslakey VERSION 0.1.0)
