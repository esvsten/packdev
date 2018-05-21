bin_PROGRAMS = packdev

include_HEADERS = \
    cp/packdev_spd_config.h \
    cp/packdev_session.h \
    cp/packdev_l3_config.h \
    cp/packdev_l2_config.h \
    cp/packdev_acl_config.h \
    cp/packdev_sa_config.h \
    cp/packdev_ipv4_flow.h 

include_HEADERS += \
    fp/packdev_ipv4.h \
    fp/packdev_eth.h \
    fp/packdev_esp.h \
    fp/packdev_packet.h \
    fp/packdev_udp.h \
    fp/packdev_nbr.h 

include_HEADERS += \
    sys/packdev_config.h \
    sys/packdev_port.h \
    sys/packdev_crypto.h \
    sys/packdev_common.h 

packdev_SOURCES = \
    packdev.c

packdev_SOURCES += \
    fp/packdev_udp.c \
    fp/packdev_ipv4.c \
    fp/packdev_eth.c \
    fp/packdev_esp.c \
    fp/packdev_packet.c \
    fp/packdev_nbr.c

packdev_SOURCES += \
    cp/packdev_sa_config.c \
    cp/packdev_l3_config.c \
    cp/packdev_l2_config.c \
    cp/packdev_ipv4_flow.c

packdev_SOURCES += \
    sys/packdev_port.c \
    sys/packdev_crypto.c \
    sys/packdev_config.c
