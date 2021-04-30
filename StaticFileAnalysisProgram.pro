QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

LIBS += /lib/x86_64-linux-gnu/libcapstone.so

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    main.cpp \
    staticfileanalyser.cpp

HEADERS += \
    staticfileanalyser.h

FORMS += \
    staticfileanalyser.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    Resources/StaticFileAnalysisProgram.qrc

DISTFILES += \
    Resources/Icons/MenuBar/File Menu/CloseFile.png \
    Resources/Icons/MenuBar/File Menu/CloseFile.png \
    Resources/Icons/MenuBar/File Menu/OpenFile.png \
    Resources/Icons/MenuBar/File Menu/OpenFile.png \
    Resources/Icons/MenuBar/File Menu/SaveFile.png \
    Resources/Icons/MenuBar/File Menu/SaveFile.png \
    Resources/Icons/MenuBar/Window Menu/EnterFullscreen.png \
    Resources/Icons/MenuBar/Window Menu/EnterFullscreen.png \
    Resources/Icons/MenuBar/Window Menu/MaximiseScreen.png \
    Resources/Icons/MenuBar/Window Menu/MaximiseScreen.png \
    Resources/Icons/MenuBar/Window Menu/MinimiseScreen.png \
    Resources/Icons/MenuBar/Window Menu/MinimiseScreen.png \
    Resources/Icons/MenuBar/Window Menu/RestoreScreen.png \
    Resources/Icons/MenuBar/Window Menu/RestoreScreen.png
