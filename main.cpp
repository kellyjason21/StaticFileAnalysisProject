#include "staticfileanalyser.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    StaticFileAnalyser w;
    w.setWindowTitle("New File");
    a.setApplicationDisplayName("Static File Analysis Project");
    w.show();
    return a.exec();
}
