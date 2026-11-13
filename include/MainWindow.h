#pragma once

#include <QMainWindow>
#include <QTabWidget>
#include <QTableWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
#include <QTextEdit>
#include <QPushButton>
#include <QProgressBar>
#include <QSplitter>
#include <QTimer>
#include <memory>
#include "InfrastructureContainer.h"

// Головне графічне вікно центру моніторингу серверної інфраструктури та кібербезпеки
class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override = default;

private slots:
    // Дії над серверами
    void onAddNode();
    void onEditNodeTelemetry();
    void onDeleteNode();
    void onNodeSearchChanged(const QString& text);
    void onNodeSelectionChanged();

    // Дії над інцидентами
    void onResolveIncident();
    void onRunSecurityAudit();
    void onStrategyChanged(int index);
    void onIncidentSearchChanged(const QString& text);
    void onIncidentSelectionChanged();

    // Симулятор атак (для тестування одногрупниками)
    void onSimulateDDoS();
    void onSimulateBruteForce();
    void onSimulateCpuSpike();
    void onSimulateDbBreach();
    void onSimulateServerCrash();
    void onRestoreAllNodes();
    void onTelemetryHeartbeat();

    // Файлові операції
    void onOpenFile();
    void onSaveFile();
    void onExportReport();
    void onLoadSampleData();

private:
    void setupUi();
    void setupToolBar();
    void setupFleetTab();
    void setupSecurityTab();
    void setupSimulatorTab();
    void setupDetailsPanel();
    void setupStatusBar();
    void applyStyles();

    void refreshNodesTable();
    void refreshIncidentsTable();
    void updateStatusBar();
    void updateNodeDetails(int nodeId);
    void updateIncidentDetails(int incidentId);

    InfrastructureContainer m_container;
    QString m_currentFilePath;

    // Віджети інтерфейсу
    QTabWidget* m_tabWidget;

    // 1. Вкладка парку серверів
    QTableWidget* m_nodesTable;
    QLineEdit* m_nodeSearchEdit;

    // 2. Вкладка інцидентів
    QTableWidget* m_incidentsTable;
    QLineEdit* m_incidentSearchEdit;
    QComboBox* m_strategyCombo;

    // 3. Панель деталей
    QLabel* m_detailTypeLabel;
    QLabel* m_detailTitleLabel;
    QLabel* m_detailSubtitleLabel;
    QWidget* m_telemetryWidget;
    QLabel* m_cpuLabel;
    QProgressBar* m_cpuBar;
    QLabel* m_ramLabel;
    QProgressBar* m_ramBar;
    QTextEdit* m_detailInfoText;
    QPushButton* m_detailActionBtn;

    // Фоновий таймер динамічної телеметрії (Real-time Heartbeat)
    QTimer* m_heartbeatTimer;

    // Статусна панель
    QLabel* m_statusFleetLabel;
    QLabel* m_statusAlertsLabel;
    QLabel* m_statusStrategyLabel;
};
