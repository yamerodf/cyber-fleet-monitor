#include <QApplication>
#include <QStyleFactory>
#include <QPalette>
#include "MainWindow.h"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("CyberFleetMonitor");
    app.setOrganizationName("TNTU_SP22");

    // Застосування стилю Fusion для уніфікованого відображення на різних ОС
    app.setStyle(QStyleFactory::create("Fusion"));

    // Світла контрастна палітра (запобігає колізіям із системними темними темами)
    QPalette lightPalette;
    lightPalette.setColor(QPalette::Window, QColor(248, 249, 250));
    lightPalette.setColor(QPalette::WindowText, QColor(30, 41, 59));
    lightPalette.setColor(QPalette::Base, QColor(255, 255, 255));
    lightPalette.setColor(QPalette::AlternateBase, QColor(241, 245, 249));
    lightPalette.setColor(QPalette::ToolTipBase, QColor(255, 255, 255));
    lightPalette.setColor(QPalette::ToolTipText, QColor(30, 41, 59));
    lightPalette.setColor(QPalette::Text, QColor(30, 41, 59));
    lightPalette.setColor(QPalette::Button, QColor(241, 245, 249));
    lightPalette.setColor(QPalette::ButtonText, QColor(30, 41, 59));
    lightPalette.setColor(QPalette::BrightText, Qt::red);
    lightPalette.setColor(QPalette::Link, QColor(37, 99, 235));
    lightPalette.setColor(QPalette::Highlight, QColor(59, 130, 246));
    lightPalette.setColor(QPalette::HighlightedText, Qt::white);
    app.setPalette(lightPalette);

    MainWindow window;
    window.show();

    return app.exec();
}
