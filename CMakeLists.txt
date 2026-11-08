cmake_minimum_required(VERSION 3.16)
project(CyberFleetMonitor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Автоматична генерація MOC для сигналів і слотів Qt
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

add_compile_options(-Wall -Wextra -Wpedantic)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets)

include_directories(include)

# Заголовні файли архітектури
set(HEADER_FILES
    include/MonitoringExceptions.h
    include/InfrastructureNode.h
    include/SpecificNodes.h
    include/SecurityIncident.h
    include/SpecificIncidents.h
    include/AnalysisStrategy.h
    include/InfrastructureContainer.h
    include/NodeDialogs.h
    include/MainWindow.h
)

# Вихідні файли бізнес-логіки та графічного інтерфейсу
set(LIB_SOURCES
    src/InfrastructureNode.cpp
    src/SpecificNodes.cpp
    src/SecurityIncident.cpp
    src/SpecificIncidents.cpp
    src/AnalysisStrategy.cpp
    src/InfrastructureContainer.cpp
    src/NodeDialogs.cpp
    src/MainWindow.cpp
)

add_library(cyber_monitor_lib STATIC
    ${HEADER_FILES}
    ${LIB_SOURCES}
)
target_link_libraries(cyber_monitor_lib PUBLIC Qt6::Core Qt6::Widgets)

# Головний виконуваний застосунок
add_executable(cyber_monitor src/main.cpp)
target_link_libraries(cyber_monitor PRIVATE cyber_monitor_lib Qt6::Widgets)

# Модульні тести
add_executable(test_monitoring tests/test_monitoring.cpp)
target_link_libraries(test_monitoring PRIVATE cyber_monitor_lib Qt6::Core Qt6::Widgets)
