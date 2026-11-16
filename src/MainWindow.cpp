#include "MainWindow.h"
#include "NodeDialogs.h"
#include "SpecificNodes.h"
#include "MonitoringExceptions.h"
#include <algorithm>

#include <QToolBar>
#include <QStatusBar>
#include <QHeaderView>
#include <QMessageBox>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGroupBox>
#include <QInputDialog>
#include <QAbstractButton>
#include <QTabBar>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
      m_currentFilePath("data/infrastructure.json"),
      m_heartbeatTimer(new QTimer(this)) {
    setupUi();
    applyStyles();

    m_container.loadSampleInfrastructure();
    refreshNodesTable();
    refreshIncidentsTable();
    updateStatusBar();

    if (m_nodesTable->rowCount() > 0) {
        m_nodesTable->selectRow(0);
    }

    // Фоновий таймер живої пульсації телеметрії серверів
    connect(m_heartbeatTimer, &QTimer::timeout, this, &MainWindow::onTelemetryHeartbeat);
    m_heartbeatTimer->start(2500); // Оновлення кожні 2.5 секунди
}

void MainWindow::setupUi() {
    setWindowTitle("CyberFleetMonitor — Центр моніторингу серверної інфраструктури та кібербезпеки");
    resize(1240, 750);

    setupToolBar();

    auto* centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    auto* mainLayout = new QHBoxLayout(centralWidget);
    mainLayout->setContentsMargins(10, 8, 10, 8);
    mainLayout->setSpacing(10);

    // Спліттер між головними вкладками та карткою деталей
    auto* splitter = new QSplitter(Qt::Horizontal, this);

    m_tabWidget = new QTabWidget(this);
    setupFleetTab();
    setupSecurityTab();
    setupSimulatorTab();

    connect(m_tabWidget, &QTabWidget::currentChanged, this, [this](int index) {
        if (index == 0 || index == 2) {
            onNodeSelectionChanged();
        } else if (index == 1) {
            onIncidentSelectionChanged();
        }
    });

    splitter->addWidget(m_tabWidget);

    setupDetailsPanel();
    auto* detailsBox = new QGroupBox("Панель телеметрії та властивостей", this);
    auto* detailsLayout = new QVBoxLayout(detailsBox);
    detailsLayout->addWidget(m_detailTypeLabel);
    detailsLayout->addWidget(m_detailTitleLabel);
    detailsLayout->addWidget(m_detailSubtitleLabel);
    detailsLayout->addWidget(m_telemetryWidget);
    detailsLayout->addWidget(m_detailInfoText, 1);
    detailsLayout->addWidget(m_detailActionBtn);

    splitter->addWidget(detailsBox);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 1);
    splitter->setSizes({820, 380});

    mainLayout->addWidget(splitter);

    setupStatusBar();

    // Інтерактивний курсор-рука (PointingHandCursor) для всіх кнопок інтерфейсу
    for (auto* btn : findChildren<QAbstractButton*>()) {
        btn->setCursor(Qt::PointingHandCursor);
    }
    if (m_tabWidget && m_tabWidget->tabBar()) {
        m_tabWidget->tabBar()->setCursor(Qt::PointingHandCursor);
    }
}

void MainWindow::setupToolBar() {
    auto* toolBar = addToolBar("Головні інструменти");
    toolBar->setMovable(false);

    toolBar->addAction("➕ Додати вузол", this, &MainWindow::onAddNode);
    toolBar->addAction("⚡ Запустити аудит", this, &MainWindow::onRunSecurityAudit);
    toolBar->addSeparator();
    toolBar->addAction("📂 Відкрити файл", this, &MainWindow::onOpenFile);
    toolBar->addAction("💾 Зберегти JSON", this, &MainWindow::onSaveFile);
    toolBar->addAction("📄 Експорт звіту", this, &MainWindow::onExportReport);
    toolBar->addSeparator();
    toolBar->addAction("🔄 Демо-дані", this, &MainWindow::onLoadSampleData);
}

void MainWindow::setupFleetTab() {
    auto* fleetWidget = new QWidget(this);
    auto* layout = new QVBoxLayout(fleetWidget);

    auto* searchLayout = new QHBoxLayout();
    auto* searchLabel = new QLabel("🔍 Пошук вузла:", this);
    searchLabel->setStyleSheet("font-weight: bold;");

    m_nodeSearchEdit = new QLineEdit(this);
    m_nodeSearchEdit->setPlaceholderText("Фільтрація за назвою, IP-адресою, локацією чи типом...");
    m_nodeSearchEdit->setMinimumWidth(220);
    connect(m_nodeSearchEdit, &QLineEdit::textChanged, this, &MainWindow::onNodeSearchChanged);

    auto* addBtn = new QPushButton("➕ Додати вузол", this);
    auto* editBtn = new QPushButton("✏️ Змінити телеметрію", this);
    auto* delBtn = new QPushButton("🗑️ Видалити", this);

    connect(addBtn, &QPushButton::clicked, this, &MainWindow::onAddNode);
    connect(editBtn, &QPushButton::clicked, this, &MainWindow::onEditNodeTelemetry);
    connect(delBtn, &QPushButton::clicked, this, &MainWindow::onDeleteNode);

    searchLayout->addWidget(searchLabel);
    searchLayout->addWidget(m_nodeSearchEdit, 1);
    searchLayout->addWidget(addBtn);
    searchLayout->addWidget(editBtn);
    searchLayout->addWidget(delBtn);

    layout->addLayout(searchLayout);

    m_nodesTable = new QTableWidget(this);
    m_nodesTable->setColumnCount(7);
    m_nodesTable->setHorizontalHeaderLabels({"ID", "Тип вузла", "Назва", "IP-адреса", "Локація", "Навантаження (CPU/RAM)", "Статус"});
    m_nodesTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_nodesTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_nodesTable->setAlternatingRowColors(true);
    m_nodesTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_nodesTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_nodesTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_nodesTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    m_nodesTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);

    connect(m_nodesTable, &QTableWidget::itemSelectionChanged, this, &MainWindow::onNodeSelectionChanged);
    connect(m_nodesTable, &QTableWidget::cellDoubleClicked, this, [this](int, int) { onEditNodeTelemetry(); });

    layout->addWidget(m_nodesTable);
    m_tabWidget->addTab(fleetWidget, "🖥️ Парк серверів (Fleet Overview)");
}

void MainWindow::setupSecurityTab() {
    auto* secWidget = new QWidget(this);
    auto* layout = new QVBoxLayout(secWidget);

    auto* controlLayout = new QHBoxLayout();
    auto* searchLabel = new QLabel("🔍 Фільтр загроз:", this);
    searchLabel->setStyleSheet("font-weight: bold;");

    m_incidentSearchEdit = new QLineEdit(this);
    m_incidentSearchEdit->setPlaceholderText("Пошук інцидентів...");
    m_incidentSearchEdit->setMinimumWidth(160);
    connect(m_incidentSearchEdit, &QLineEdit::textChanged, this, &MainWindow::onIncidentSearchChanged);

    auto* stratLabel = new QLabel("Стратегія:", this);
    stratLabel->setStyleSheet("font-weight: bold; margin-left: 6px;");

    m_strategyCombo = new QComboBox(this);
    m_strategyCombo->addItems({"Пороговий сигнатурний аналіз (Threshold)",
                              "Евристичний поведінковий моніторинг (Heuristic)"});
    connect(m_strategyCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onStrategyChanged);

    auto* auditBtn = new QPushButton("⚡ Запустити аудит", this);
    auto* resolveBtn = new QPushButton("🛡️ Розслідувати / Закрити", this);
    resolveBtn->setStyleSheet("background-color: #dbeafe; font-weight: bold;");

    connect(auditBtn, &QPushButton::clicked, this, &MainWindow::onRunSecurityAudit);
    connect(resolveBtn, &QPushButton::clicked, this, &MainWindow::onResolveIncident);

    controlLayout->addWidget(searchLabel);
    controlLayout->addWidget(m_incidentSearchEdit, 1);
    controlLayout->addWidget(stratLabel);
    controlLayout->addWidget(m_strategyCombo);
    controlLayout->addWidget(auditBtn);
    controlLayout->addWidget(resolveBtn);

    layout->addLayout(controlLayout);

    m_incidentsTable = new QTableWidget(this);
    m_incidentsTable->setColumnCount(7);
    m_incidentsTable->setHorizontalHeaderLabels({"ID", "Категорія загрози", "Цільовий вузол", "IP атакуючого", "Рівень небезпеки", "Статус", "Час виявлення"});
    m_incidentsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_incidentsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_incidentsTable->setAlternatingRowColors(true);
    m_incidentsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_incidentsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_incidentsTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_incidentsTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    m_incidentsTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    m_incidentsTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);

    connect(m_incidentsTable, &QTableWidget::itemSelectionChanged, this, &MainWindow::onIncidentSelectionChanged);
    connect(m_incidentsTable, &QTableWidget::cellDoubleClicked, this, [this](int, int) { onResolveIncident(); });

    layout->addWidget(m_incidentsTable);
    m_tabWidget->addTab(secWidget, "🛡️ Журнал інцидентів SOC (Security Alerts)");
}

void MainWindow::setupSimulatorTab() {
    auto* simWidget = new QWidget(this);
    auto* layout = new QVBoxLayout(simWidget);

    auto* descLabel = new QLabel(
        "<b>Симулятор кібератак та аномалій інфраструктури:</b><br>"
        "Цей інструмент призначений для інтерактивного тестування одногрупниками реакції системи моніторингу.<br>"
        "Оберіть сценарій атаки, і система в реальному часі оновить метрики та згенерує відповідний інцидент у журналі SOC.",
        this
    );
    descLabel->setStyleSheet("padding: 10px; background-color: #f1f5f9; border-radius: 6px; font-size: 13px;");
    layout->addWidget(descLabel);

    auto* gridLayout = new QGridLayout();

    auto* ddosBtn = new QPushButton("🌊 1. Змоделювати потужну DDoS-атаку (SYN Flood на шлюз)", this);
    auto* bruteBtn = new QPushButton("🔑 2. Змоделювати Brute-Force злам SSH (масований перебір паролів)", this);
    auto* cpuBtn = new QPushButton("🔥 3. Перевантажити процесор та пам'ять сервера (Mining / Spike)", this);
    auto* dbBtn = new QPushButton("🔓 4. Імітувати витік та несанкціонований доступ до бази даних", this);
    auto* crashBtn = new QPushButton("💥 5. Змоделювати аварійне падіння вузла (Server Crash / Offline)", this);
    auto* restoreBtn = new QPushButton("💚 6. Відновити нормальний робочий стан усіх серверів", this);

    ddosBtn->setStyleSheet("padding: 12px; font-size: 13px; text-align: left;");
    bruteBtn->setStyleSheet("padding: 12px; font-size: 13px; text-align: left;");
    cpuBtn->setStyleSheet("padding: 12px; font-size: 13px; text-align: left;");
    dbBtn->setStyleSheet("padding: 12px; font-size: 13px; text-align: left;");
    crashBtn->setStyleSheet("padding: 12px; font-size: 13px; text-align: left; color: #b91c1c;");
    restoreBtn->setStyleSheet("padding: 12px; font-size: 13px; text-align: left; color: #15803d; font-weight: bold;");

    connect(ddosBtn, &QPushButton::clicked, this, &MainWindow::onSimulateDDoS);
    connect(bruteBtn, &QPushButton::clicked, this, &MainWindow::onSimulateBruteForce);
    connect(cpuBtn, &QPushButton::clicked, this, &MainWindow::onSimulateCpuSpike);
    connect(dbBtn, &QPushButton::clicked, this, &MainWindow::onSimulateDbBreach);
    connect(crashBtn, &QPushButton::clicked, this, &MainWindow::onSimulateServerCrash);
    connect(restoreBtn, &QPushButton::clicked, this, &MainWindow::onRestoreAllNodes);

    gridLayout->addWidget(ddosBtn, 0, 0);
    gridLayout->addWidget(bruteBtn, 0, 1);
    gridLayout->addWidget(cpuBtn, 1, 0);
    gridLayout->addWidget(dbBtn, 1, 1);
    gridLayout->addWidget(crashBtn, 2, 0);
    gridLayout->addWidget(restoreBtn, 2, 1);

    layout->addLayout(gridLayout);
    layout->addStretch();

    m_tabWidget->addTab(simWidget, "🧪 Симулятор атак (Peer Testing Lab)");
}

void MainWindow::setupDetailsPanel() {
    m_detailTypeLabel = new QLabel("ТИП ОБ'ЄКТА", this);
    m_detailTypeLabel->setStyleSheet("font-size: 11px; font-weight: bold; color: #2563EB; text-transform: uppercase; letter-spacing: 0.5px;");

    m_detailTitleLabel = new QLabel("Оберіть елемент у таблиці", this);
    m_detailTitleLabel->setStyleSheet("font-size: 15px; font-weight: bold; color: #0F172A; margin-top: 2px;");
    m_detailTitleLabel->setWordWrap(true);

    m_detailSubtitleLabel = new QLabel("", this);
    m_detailSubtitleLabel->setStyleSheet("font-size: 12px; color: #64748B; margin-bottom: 6px;");
    m_detailSubtitleLabel->setWordWrap(true);

    // Блок графічних шкал телеметрії (як у Wireframe прототипі)
    m_telemetryWidget = new QWidget(this);
    auto* telemetryLayout = new QVBoxLayout(m_telemetryWidget);
    telemetryLayout->setContentsMargins(0, 4, 0, 8);
    telemetryLayout->setSpacing(4);

    m_cpuLabel = new QLabel("Навантаження CPU: 0.0%", m_telemetryWidget);
    m_cpuLabel->setStyleSheet("font-size: 12px; font-weight: bold; color: #334155;");
    m_cpuBar = new QProgressBar(m_telemetryWidget);
    m_cpuBar->setRange(0, 100);
    m_cpuBar->setValue(0);
    m_cpuBar->setTextVisible(false);
    m_cpuBar->setFixedHeight(16);
    m_cpuBar->setStyleSheet(R"(
        QProgressBar {
            background-color: #E2E8F0;
            border: 1px solid #CBD5E1;
            border-radius: 4px;
        }
        QProgressBar::chunk {
            background-color: #3B82F6;
            border-radius: 3px;
        }
    )");

    m_ramLabel = new QLabel("Використання RAM: 0.0%", m_telemetryWidget);
    m_ramLabel->setStyleSheet("font-size: 12px; font-weight: bold; color: #334155; margin-top: 4px;");
    m_ramBar = new QProgressBar(m_telemetryWidget);
    m_ramBar->setRange(0, 100);
    m_ramBar->setValue(0);
    m_ramBar->setTextVisible(false);
    m_ramBar->setFixedHeight(16);
    m_ramBar->setStyleSheet(R"(
        QProgressBar {
            background-color: #E2E8F0;
            border: 1px solid #CBD5E1;
            border-radius: 4px;
        }
        QProgressBar::chunk {
            background-color: #10B981;
            border-radius: 3px;
        }
    )");

    telemetryLayout->addWidget(m_cpuLabel);
    telemetryLayout->addWidget(m_cpuBar);
    telemetryLayout->addWidget(m_ramLabel);
    telemetryLayout->addWidget(m_ramBar);

    m_detailInfoText = new QTextEdit(this);
    m_detailInfoText->setReadOnly(true);
    m_detailInfoText->setStyleSheet("background-color: #ffffff; color: #1e293b; border: 1px solid #cbd5e1; border-radius: 6px; padding: 6px; font-size: 12px;");

    m_detailActionBtn = new QPushButton("Дія над об'єктом", this);
    m_detailActionBtn->setEnabled(false);
    m_detailActionBtn->setCursor(Qt::PointingHandCursor);
    m_detailActionBtn->setStyleSheet(R"(
        QPushButton {
            background-color: #2563EB;
            color: #FFFFFF;
            font-weight: bold;
            font-size: 13px;
            padding: 8px 14px;
            border: 1px solid #1D4ED8;
            border-radius: 6px;
        }
        QPushButton:hover { background-color: #1D4ED8; }
        QPushButton:pressed { background-color: #1E40AF; }
        QPushButton:disabled { background-color: #94A3B8; border-color: #94A3B8; color: #E2E8F0; }
    )");
}

void MainWindow::setupStatusBar() {
    m_statusFleetLabel = new QLabel(this);
    m_statusAlertsLabel = new QLabel(this);
    m_statusStrategyLabel = new QLabel(this);

    statusBar()->addPermanentWidget(m_statusFleetLabel, 2);
    statusBar()->addPermanentWidget(m_statusAlertsLabel, 2);
    statusBar()->addPermanentWidget(m_statusStrategyLabel, 2);
}

void MainWindow::applyStyles() {
    setStyleSheet(R"(
        QMainWindow {
            background-color: #F8F9FA;
        }
        QToolBar {
            background-color: #FFFFFF;
            border-bottom: 1px solid #E2E8F0;
            padding: 4px;
            spacing: 6px;
        }
        QToolButton {
            background: transparent;
            border: 1px solid transparent;
            border-radius: 4px;
            padding: 5px 10px;
            font-size: 12px;
            font-weight: 500;
        }
        QToolButton:hover {
            background-color: #EDF2F7;
            border: 1px solid #CBD5E0;
        }
        QTableWidget {
            background-color: #FFFFFF;
            alternate-background-color: #F8FAFC;
            color: #1E293B;
            border: 1px solid #CBD5E0;
            border-radius: 6px;
            font-size: 13px;
            gridline-color: #E2E8F0;
        }
        QTableWidget::item:selected {
            background-color: #DBEAFE;
            color: #1E40AF;
        }
        QHeaderView::section {
            background-color: #F1F5F9;
            color: #475569;
            padding: 6px;
            border: none;
            border-right: 1px solid #E2E8F0;
            border-bottom: 1px solid #CBD5E0;
            font-weight: bold;
            font-size: 12px;
        }
        QTabWidget::pane {
            border: 1px solid #CBD5E0;
            background: #FFFFFF;
            border-radius: 6px;
        }
        QTabBar::tab {
            background: #F1F5F9;
            color: #475569;
            padding: 8px 16px;
            font-weight: 600;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background: #FFFFFF;
            color: #2563EB;
            border: 1px solid #CBD5E0;
            border-bottom: 1px solid #FFFFFF;
        }
        QGroupBox {
            background-color: #FFFFFF;
            border: 1px solid #CBD5E0;
            border-radius: 6px;
            margin-top: 10px;
            font-weight: bold;
            color: #334155;
            font-size: 12px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 4px;
        }
        QLineEdit, QComboBox, QTextEdit {
            background-color: #FFFFFF;
            border: 1px solid #CBD5E0;
            border-radius: 4px;
            padding: 4px 8px;
            font-size: 12px;
            color: #1E293B;
        }
        QPushButton {
            background-color: #FFFFFF;
            border: 1px solid #CBD5E0;
            border-radius: 4px;
            padding: 5px 12px;
            font-size: 12px;
            font-weight: 500;
            color: #1E293B;
        }
        QPushButton:hover {
            background-color: #F8FAFC;
            border-color: #94A3B8;
        }
        QPushButton:pressed {
            background-color: #E2E8F0;
        }
        QStatusBar {
            background-color: #F1F5F9;
            color: #475569;
            font-size: 12px;
            border-top: 1px solid #E2E8F0;
        }
    )");
}

void MainWindow::refreshNodesTable() {
    auto nodes = m_container.filterNodes(m_nodeSearchEdit ? m_nodeSearchEdit->text() : "");
    m_nodesTable->setRowCount(static_cast<int>(nodes.size()));

    for (int r = 0; r < static_cast<int>(nodes.size()); ++r) {
        const auto& n = nodes[r];
        auto* itemId = new QTableWidgetItem(QString::number(n->id()));
        auto* itemType = new QTableWidgetItem(n->typeName());
        auto* itemName = new QTableWidgetItem(n->name());
        auto* itemIp = new QTableWidgetItem(n->ipAddress());
        auto* itemLoc = new QTableWidgetItem(n->location());

        QString loadStr = QString("CPU: %1% | RAM: %2%")
            .arg(n->cpuUsage(), 0, 'f', 1).arg(n->ramUsage(), 0, 'f', 1);
        auto* itemLoad = new QTableWidgetItem(loadStr);

        auto* itemStatus = new QTableWidgetItem(n->statusString());
        if (n->status() == NodeStatus::Online) {
            itemStatus->setForeground(QColor("#16a34a"));
        } else if (n->status() == NodeStatus::Warning) {
            itemStatus->setForeground(QColor("#d97706"));
        } else {
            itemStatus->setForeground(QColor("#dc2626"));
        }

        m_nodesTable->setItem(r, 0, itemId);
        m_nodesTable->setItem(r, 1, itemType);
        m_nodesTable->setItem(r, 2, itemName);
        m_nodesTable->setItem(r, 3, itemIp);
        m_nodesTable->setItem(r, 4, itemLoc);
        m_nodesTable->setItem(r, 5, itemLoad);
        m_nodesTable->setItem(r, 6, itemStatus);
    }
}

void MainWindow::refreshIncidentsTable() {
    auto incidents = m_container.filterIncidents(m_incidentSearchEdit ? m_incidentSearchEdit->text() : "");
    m_incidentsTable->setRowCount(static_cast<int>(incidents.size()));

    for (int r = 0; r < static_cast<int>(incidents.size()); ++r) {
        const auto& inc = incidents[r];
        auto* itemId = new QTableWidgetItem(QString("#%1").arg(inc->id()));
        auto* itemCat = new QTableWidgetItem(inc->categoryName());
        auto* itemTarget = new QTableWidgetItem(inc->targetNodeName());
        auto* itemIp = new QTableWidgetItem(inc->sourceIp());
        auto* itemSev = new QTableWidgetItem(inc->severityString());

        if (inc->severity() == IncidentSeverity::Critical) {
            itemSev->setForeground(QColor("#dc2626"));
        } else if (inc->severity() == IncidentSeverity::High) {
            itemSev->setForeground(QColor("#ea580c"));
        } else {
            itemSev->setForeground(QColor("#2563eb"));
        }

        auto* itemStatus = new QTableWidgetItem(inc->statusString());
        if (inc->status() == IncidentStatus::Resolved) {
            itemStatus->setForeground(QColor("#16a34a"));
        } else {
            itemStatus->setForeground(QColor("#b91c1c"));
        }

        auto* itemTime = new QTableWidgetItem(inc->timestamp().toString("dd.MM.yyyy hh:mm:ss"));

        m_incidentsTable->setItem(r, 0, itemId);
        m_incidentsTable->setItem(r, 1, itemCat);
        m_incidentsTable->setItem(r, 2, itemTarget);
        m_incidentsTable->setItem(r, 3, itemIp);
        m_incidentsTable->setItem(r, 4, itemSev);
        m_incidentsTable->setItem(r, 5, itemStatus);
        m_incidentsTable->setItem(r, 6, itemTime);
    }
}

void MainWindow::updateStatusBar() {
    m_statusFleetLabel->setText(
        QString("🖥️ Вузлів: %1 | Онлайн: %2 | Критичних: %3 | Сер. CPU: %4%")
            .arg(m_container.totalNodes())
            .arg(m_container.onlineNodes())
            .arg(m_container.criticalNodes())
            .arg(m_container.averageCpuUsage(), 0, 'f', 1)
    );

    m_statusAlertsLabel->setText(
        QString("🛡️ Активних загроз: %1 (Всього: %2)")
            .arg(m_container.activeIncidentsCount())
            .arg(m_container.incidents().size())
    );

    if (m_container.currentStrategy()) {
        m_statusStrategyLabel->setText("Стратегія: " + m_container.currentStrategy()->strategyName());
    }
}

void MainWindow::onNodeSelectionChanged() {
    int row = m_nodesTable->currentRow();
    if (row < 0 || row >= m_nodesTable->rowCount()) return;

    int nodeId = m_nodesTable->item(row, 0)->text().toInt();
    updateNodeDetails(nodeId);
}

void MainWindow::onIncidentSelectionChanged() {
    int row = m_incidentsTable->currentRow();
    if (row < 0 || row >= m_incidentsTable->rowCount()) return;

    QString idText = m_incidentsTable->item(row, 0)->text().remove('#');
    int incId = idText.toInt();
    updateIncidentDetails(incId);
}

void MainWindow::updateNodeDetails(int nodeId) {
    auto node = m_container.findNodeById(nodeId);
    if (!node) return;

    m_telemetryWidget->show();

    m_detailTypeLabel->setText("🖥️ " + node->typeName().toUpper() + QString(" (ID: %1)").arg(node->id()));
    m_detailTitleLabel->setText(node->name());
    m_detailSubtitleLabel->setText(QString("IP: %1 | Локація: %2").arg(node->ipAddress()).arg(node->location()));

    // Оновлення графічних шкал телеметрії
    double cpu = node->cpuUsage();
    double ram = node->ramUsage();
    m_cpuLabel->setText(QString("Навантаження CPU: %1%").arg(cpu, 0, 'f', 1));
    m_cpuBar->setValue(static_cast<int>(std::clamp(cpu, 0.0, 100.0)));
    QString cpuColor = (cpu >= 85.0) ? "#EF4444" : ((cpu >= 65.0) ? "#F59E0B" : "#3B82F6");
    m_cpuBar->setStyleSheet(QString(R"(
        QProgressBar { background-color: #E2E8F0; border: 1px solid #CBD5E1; border-radius: 4px; }
        QProgressBar::chunk { background-color: %1; border-radius: 3px; }
    )").arg(cpuColor));

    m_ramLabel->setText(QString("Використання RAM: %1%").arg(ram, 0, 'f', 1));
    m_ramBar->setValue(static_cast<int>(std::clamp(ram, 0.0, 100.0)));
    QString ramColor = (ram >= 85.0) ? "#EF4444" : ((ram >= 70.0) ? "#F59E0B" : "#10B981");
    m_ramBar->setStyleSheet(QString(R"(
        QProgressBar { background-color: #E2E8F0; border: 1px solid #CBD5E1; border-radius: 4px; }
        QProgressBar::chunk { background-color: %1; border-radius: 3px; }
    )").arg(ramColor));

    // Специфікація характеристик вузла (HTML картка як у прототипі)
    QString statusCol = (node->status() == NodeStatus::Online) ? "#16A34A" :
                        ((node->status() == NodeStatus::Warning) ? "#D97706" :
                        ((node->status() == NodeStatus::Critical) ? "#DC2626" : "#475569"));

    QString specsHtml = "";
    if (auto srv = std::dynamic_pointer_cast<ServerNode>(node)) {
        specsHtml += QString("<tr><td style='color: #64748B;'>Операційна система:</td><td style='font-weight: 600; color: #0F172A;'>%1</td></tr>").arg(srv->osVersion());
        specsHtml += QString("<tr><td style='color: #64748B;'>Активних служб:</td><td style='font-weight: 600; color: #0F172A;'>%1 контейнерів</td></tr>").arg(srv->activeServices());
        specsHtml += QString("<tr><td style='color: #64748B;'>Використання SSD:</td><td style='font-weight: 600; color: #0F172A;'>%1% зайнято</td></tr>").arg(srv->diskUsage(), 0, 'f', 1);
        specsHtml += QString("<tr><td style='color: #64748B;'>SSH порт управління:</td><td style='font-weight: 600; color: #0F172A;'>%1 (%2)</td></tr>").arg(srv->sshPort()).arg(srv->sshPort() == 22 ? "Default" : "Custom");
    } else if (auto db = std::dynamic_pointer_cast<DatabaseNode>(node)) {
        specsHtml += QString("<tr><td style='color: #64748B;'>Рушій СУБД:</td><td style='font-weight: 600; color: #0F172A;'>%1</td></tr>").arg(db->dbEngine());
        specsHtml += QString("<tr><td style='color: #64748B;'>Потік запитів (QPS):</td><td style='font-weight: 600; color: #0F172A;'>%1 req/sec</td></tr>").arg(db->queriesPerSecond(), 0, 'f', 1);
        specsHtml += QString("<tr><td style='color: #64748B;'>Активних з'єднань:</td><td style='font-weight: 600; color: #0F172A;'>%1 пул клієнтів</td></tr>").arg(db->activeConnections());
        specsHtml += QString("<tr><td style='color: #64748B;'>Розмір бази даних:</td><td style='font-weight: 600; color: #0F172A;'>%1 GB</td></tr>").arg(db->storageGb(), 0, 'f', 1);
    } else if (auto gw = std::dynamic_pointer_cast<NetworkGatewayNode>(node)) {
        specsHtml += QString("<tr><td style='color: #64748B;'>Пропускна здатність:</td><td style='font-weight: 600; color: #0F172A;'>%1 Mbps</td></tr>").arg(gw->bandwidthMbps(), 0, 'f', 1);
        specsHtml += QString("<tr><td style='color: #64748B;'>Втрата пакетів:</td><td style='font-weight: 600; color: #0F172A;'>%1%</td></tr>").arg(gw->packetDropRate(), 0, 'f', 2);
        specsHtml += QString("<tr><td style='color: #64748B;'>Фаєрвол (Stateful):</td><td style='font-weight: 600; color: #0F172A;'>%1</td></tr>").arg(gw->isFirewallActive() ? "✅ Активовано" : "❌ Вимкнено");
        specsHtml += QString("<tr><td style='color: #64748B;'>Заблоковано IP:</td><td style='font-weight: 600; color: #0F172A;'>%1 адрес</td></tr>").arg(gw->blockedIpCount());
    }

    int days = node->uptimeHours() / 24;
    int hours = node->uptimeHours() % 24;

    QString html = QString(R"(
        <div style="font-family: sans-serif; font-size: 12px; line-height: 1.5;">
            <div style="font-weight: bold; color: #475569; margin-bottom: 6px; text-transform: uppercase; font-size: 11px;">Специфікація характеристик:</div>
            <table cellpadding="3" cellspacing="0" style="width: 100%; border-collapse: collapse;">
                <tr style="border-bottom: 1px solid #f1f5f9;"><td style="color: #64748B;">Час роботи (Uptime):</td><td style="font-weight: 600; color: #0F172A;">%1 год. (%2 дн. %3 год.)</td></tr>
                <tr style="border-bottom: 1px solid #f1f5f9;"><td style="color: #64748B;">Стан працездатності:</td><td style="font-weight: bold; color: %4;">%5</td></tr>
                %6
            </table>
        </div>
    )").arg(node->uptimeHours())
       .arg(days)
       .arg(hours)
       .arg(statusCol)
       .arg(node->statusString())
       .arg(specsHtml);

    m_detailInfoText->setHtml(html);
    m_detailActionBtn->setEnabled(true);
    m_detailActionBtn->setText("✏️ Змінити показники телеметрії");
    m_detailActionBtn->setStyleSheet(R"(
        QPushButton {
            background-color: #2563EB;
            color: #FFFFFF;
            font-weight: bold;
            font-size: 13px;
            padding: 8px 16px;
            border: 1px solid #1D4ED8;
            border-radius: 6px;
        }
        QPushButton:hover { background-color: #1D4ED8; }
        QPushButton:pressed { background-color: #1E40AF; }
    )");
    m_detailActionBtn->disconnect();
    connect(m_detailActionBtn, &QPushButton::clicked, this, &MainWindow::onEditNodeTelemetry);
}

void MainWindow::updateIncidentDetails(int incidentId) {
    auto inc = m_container.findIncidentById(incidentId);
    if (!inc) return;

    m_telemetryWidget->hide();

    m_detailTypeLabel->setText("🛡️ ІНЦИДЕНТ БЕЗПЕКИ SOC");
    m_detailTitleLabel->setText(QString("[%1] #%2").arg(inc->categoryName()).arg(inc->id()));
    m_detailSubtitleLabel->setText(QString("Цільовий вузол: %1 | Час: %2")
        .arg(inc->targetNodeName()).arg(inc->timestamp().toString("dd.MM.yyyy hh:mm:ss")));

    QString sevColor = (inc->severity() == IncidentSeverity::Critical) ? "#DC2626" :
                       ((inc->severity() == IncidentSeverity::High) ? "#EA580C" :
                       ((inc->severity() == IncidentSeverity::Medium) ? "#D97706" : "#2563EB"));

    QString html = QString(R"(
        <div style="font-family: sans-serif; font-size: 12px; line-height: 1.5;">
            <div style="margin-bottom: 8px;">
                <span style="background-color: %1; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">%2</span>
                &nbsp;
                <span style="color: #64748B;">Статус: <b>%3</b></span>
            </div>
            <table cellpadding="3" cellspacing="0" style="width: 100%; border-collapse: collapse;">
                <tr><td style="color: #64748B;">Джерело (IP):</td><td style="font-family: monospace; font-weight: bold;">%4</td></tr>
                <tr><td style="color: #64748B;">Опис загрози:</td><td>%5</td></tr>
            </table>
            <div style="margin-top: 8px; padding: 8px; background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 4px;">
                <div style="font-weight: bold; color: #1E293B; margin-bottom: 4px;">📋 План нейтралізації:</div>
                <div style="color: #334155;">%6</div>
            </div>
            <div style="margin-top: 6px; font-size: 11px; color: #64748B;">
                <b>Коментар вирішення:</b> %7
            </div>
        </div>
    )").arg(sevColor)
       .arg(inc->severityString())
       .arg(inc->statusString())
       .arg(inc->sourceIp())
       .arg(inc->description())
       .arg(inc->getMitigationPlan().replace("\n", "<br>"))
       .arg(inc->resolutionNotes().isEmpty() ? "<i>Ще не вирішено</i>" : inc->resolutionNotes());

    m_detailInfoText->setHtml(html);
    m_detailActionBtn->setEnabled(inc->status() != IncidentStatus::Resolved);
    m_detailActionBtn->setText("🛡️ Розслідувати / Закрити інцидент");
    m_detailActionBtn->setStyleSheet(R"(
        QPushButton {
            background-color: #0F766E;
            color: #FFFFFF;
            font-weight: bold;
            font-size: 13px;
            padding: 8px 16px;
            border: 1px solid #0D9488;
            border-radius: 6px;
        }
        QPushButton:hover { background-color: #0D9488; }
        QPushButton:pressed { background-color: #115E59; }
        QPushButton:disabled { background-color: #94A3B8; border-color: #94A3B8; color: #E2E8F0; }
    )");
    m_detailActionBtn->disconnect();
    connect(m_detailActionBtn, &QPushButton::clicked, this, &MainWindow::onResolveIncident);
}

void MainWindow::onAddNode() {
    AddNodeDialog dlg(this, m_container.nextNodeId());
    if (dlg.exec() == QDialog::Accepted) {
        auto node = dlg.getCreatedNode();
        if (node) {
            try {
                m_container.addNode(node);
                refreshNodesTable();
                updateStatusBar();
                QMessageBox::information(this, "Успіх", QString("Вузол «%1» успішно додано до парку!").arg(node->name()));
            } catch (const MonitoringException& e) {
                QMessageBox::critical(this, "Помилка додавання", e.what());
            }
        }
    }
}

void MainWindow::onEditNodeTelemetry() {
    int row = m_nodesTable->currentRow();
    if (row < 0) {
        QMessageBox::information(this, "Підказка", "Оберіть сервер у таблиці для редагування телеметрії.");
        return;
    }
    int nodeId = m_nodesTable->item(row, 0)->text().toInt();
    auto node = m_container.findNodeById(nodeId);
    if (!node) return;

    bool ok;
    double newCpu = QInputDialog::getDouble(this, "Зміна навантаження CPU",
                                           QString("Вкажіть поточний % CPU для %1:").arg(node->name()),
                                           node->cpuUsage(), 0.0, 100.0, 1, &ok);
    if (!ok) return;

    double newRam = QInputDialog::getDouble(this, "Зміна використання RAM",
                                           QString("Вкажіть поточний % RAM для %1:").arg(node->name()),
                                           node->ramUsage(), 0.0, 100.0, 1, &ok);
    if (!ok) return;

    node->setCpuUsage(newCpu);
    node->setRamUsage(newRam);
    node->updateHealthStatus();

    refreshNodesTable();
    updateNodeDetails(nodeId);
    updateStatusBar();
}

void MainWindow::onDeleteNode() {
    int row = m_nodesTable->currentRow();
    if (row < 0) return;
    int nodeId = m_nodesTable->item(row, 0)->text().toInt();
    auto node = m_container.findNodeById(nodeId);
    if (!node) return;

    auto res = QMessageBox::question(
        this, "Підтвердження видалення",
        QString("Ви дійсно бажаєте вилучити вузол «%1» (ID: %2) з моніторингу?").arg(node->name()).arg(nodeId),
        QMessageBox::Yes | QMessageBox::No
    );

    if (res == QMessageBox::Yes) {
        m_container.removeNode(nodeId);
        refreshNodesTable();
        updateStatusBar();
        m_detailInfoText->clear();
    }
}

void MainWindow::onNodeSearchChanged(const QString& text) {
    Q_UNUSED(text);
    refreshNodesTable();
}

void MainWindow::onIncidentSearchChanged(const QString& text) {
    Q_UNUSED(text);
    refreshIncidentsTable();
}

void MainWindow::onStrategyChanged(int index) {
    if (index == 0) {
        m_container.setStrategy(std::make_unique<ThresholdAnalysisStrategy>());
    } else {
        m_container.setStrategy(std::make_unique<HeuristicAnomalyStrategy>());
    }
    updateStatusBar();
}

void MainWindow::onRunSecurityAudit() {
    int added = m_container.runSecurityAudit();
    refreshIncidentsTable();
    updateStatusBar();
    if (added > 0) {
        QMessageBox::warning(this, "Аудит завершено",
            QString("Виявлено нових загроз та аномалій: %1. Деталі зафіксовано в журналі SOC.").arg(added));
        m_tabWidget->setCurrentIndex(1);
    } else {
        QMessageBox::information(this, "Аудит завершено",
            "Аномалій та перевищень порогів не виявлено. Інфраструктура функціонує в штатному режимі.");
    }
}

void MainWindow::onResolveIncident() {
    int row = m_incidentsTable->currentRow();
    if (row < 0) {
        QMessageBox::information(this, "Підказка", "Оберіть інцидент для розслідування.");
        return;
    }
    QString idText = m_incidentsTable->item(row, 0)->text().remove('#');
    int incId = idText.toInt();
    auto inc = m_container.findIncidentById(incId);
    if (!inc) return;

    ResolveIncidentDialog dlg(inc, this);
    if (dlg.exec() == QDialog::Accepted) {
        inc->resolve(dlg.getResolutionNotes());
        if (dlg.shouldBlockIp()) {
            // Шукаємо шлюз та інкрементуємо заблоковані IP
            for (const auto& node : m_container.nodes()) {
                if (node->type() == NodeType::NetworkGateway) {
                    auto gw = std::static_pointer_cast<NetworkGatewayNode>(node);
                    gw->incrementBlockedIp();
                    break;
                }
            }
        }
        refreshIncidentsTable();
        refreshNodesTable();
        updateIncidentDetails(incId);
        updateStatusBar();
        QMessageBox::information(this, "Інцидент закрито", "Заходи нейтралізації застосовано. Інцидент позначено як вирішений.");
    }
}

// ----------------- СИМУЛЯТОР АТАК (ДЛЯ ТЕСТУВАННЯ) -----------------
void MainWindow::onSimulateDDoS() {
    for (const auto& node : m_container.nodes()) {
        if (node->type() == NodeType::NetworkGateway) {
            auto gw = std::static_pointer_cast<NetworkGatewayNode>(node);
            gw->setBandwidthMbps(920.0);
            gw->setPacketDropRate(6.8);
            gw->setCpuUsage(89.0);
            gw->updateHealthStatus();
            break;
        }
    }
    auto inc = std::make_shared<DDoSAnomalyIncident>(
        m_container.nextIncidentId(), 103, "border-edge-firewall", "45.154.255.10",
        IncidentSeverity::Critical,
        "Масований сплеск UDP-трафіку (920 Mbps). Втрата пакетів перевищила 6.8%.",
        9.2, 680.0, "UDP Amp / NTP Flood"
    );
    m_container.addIncident(inc);
    refreshNodesTable();
    refreshIncidentsTable();
    updateStatusBar();
    m_tabWidget->setCurrentIndex(1);
    QMessageBox::warning(this, "Симуляція DDoS", "Спровоковано аномальний сплеск трафіку на шлюз! Створено критичний інцидент.");
}

void MainWindow::onSimulateBruteForce() {
    auto inc = std::make_shared<BruteForceIncident>(
        m_container.nextIncidentId(), 101, "prod-api-eu-central", "91.240.118.4",
        IncidentSeverity::High,
        "Атака перебором паролів за словником (виявлено 350 запитів до SSH протягом 60 сек).",
        350, "SSH Daemon / Port 2222"
    );
    m_container.addIncident(inc);
    refreshIncidentsTable();
    updateStatusBar();
    m_tabWidget->setCurrentIndex(1);
    QMessageBox::warning(this, "Симуляція Brute-Force", "Змодельовано атаку перебору облікових записів! Інцидент зареєстровано.");
}

void MainWindow::onSimulateCpuSpike() {
    for (const auto& node : m_container.nodes()) {
        if (node->type() == NodeType::GenericServer) {
            node->setCpuUsage(98.7);
            node->setRamUsage(96.2);
            node->updateHealthStatus();
            break;
        }
    }
    auto inc = std::make_shared<ResourceSpikeIncident>(
        m_container.nextIncidentId(), 101, "prod-api-eu-central", "127.0.0.1",
        IncidentSeverity::Critical,
        "Сплеск навантаження процесора до 98.7%! Підозра на несанкціонований криптомайнер або неконтрольовану рекурсію.",
        "CPU Usage", 98.7, "kworker-crypto [PID 2814]"
    );
    m_container.addIncident(inc);
    refreshNodesTable();
    refreshIncidentsTable();
    updateStatusBar();
    m_tabWidget->setCurrentIndex(0);
    QMessageBox::warning(this, "Симуляція Resource Spike", "Процесор сервера перевантажено до 98.7%! Статус сервера змінено на Critical.");
}

void MainWindow::onSimulateDbBreach() {
    for (const auto& node : m_container.nodes()) {
        if (node->type() == NodeType::DatabaseCluster) {
            auto db = std::static_pointer_cast<DatabaseNode>(node);
            db->setQueriesPerSecond(4800.0);
            db->updateHealthStatus();
            break;
        }
    }
    auto inc = std::make_shared<UnauthorizedAccessIncident>(
        m_container.nextIncidentId(), 102, "pg-cluster-primary", "194.26.29.112",
        IncidentSeverity::Critical,
        "Масове неавторизоване вивантаження хешів паролів та таблиці користувачів (SQL Injection / Data Exfiltration)!",
        "Database Schema / public.users & credentials", 99
    );
    m_container.addIncident(inc);
    refreshNodesTable();
    refreshIncidentsTable();
    updateStatusBar();
    m_tabWidget->setCurrentIndex(1);
    QMessageBox::critical(this, "Симуляція витоку БД", "Зафіксовано несанкціоноване вивантаження бази даних! Критичний інцидент зареєстровано.");
}

void MainWindow::onSimulateServerCrash() {
    for (const auto& node : m_container.nodes()) {
        if (node->type() == NodeType::GenericServer) {
            node->setStatus(NodeStatus::Offline);
            node->setCpuUsage(0.0);
            node->setRamUsage(0.0);
            break;
        }
    }
    refreshNodesTable();
    updateStatusBar();
    m_tabWidget->setCurrentIndex(0);
    QMessageBox::critical(this, "Аварія сервера", "Сервер переведено в статус Offline (повна втрата зв'язку / Heartbeat Timeout).");
}

void MainWindow::onRestoreAllNodes() {
    for (const auto& node : m_container.nodes()) {
        if (node->type() == NodeType::GenericServer) {
            node->setStatus(NodeStatus::Online);
            node->setCpuUsage(28.4);
            node->setRamUsage(45.0);
        } else if (node->type() == NodeType::DatabaseCluster) {
            auto db = std::static_pointer_cast<DatabaseNode>(node);
            db->setStatus(NodeStatus::Online);
            db->setCpuUsage(38.0);
            db->setRamUsage(55.0);
            db->setQueriesPerSecond(950.0);
        } else if (node->type() == NodeType::NetworkGateway) {
            auto gw = std::static_pointer_cast<NetworkGatewayNode>(node);
            gw->setStatus(NodeStatus::Online);
            gw->setCpuUsage(15.0);
            gw->setRamUsage(28.0);
            gw->setBandwidthMbps(380.0);
            gw->setPacketDropRate(0.01);
        }
    }
    refreshNodesTable();
    updateStatusBar();
    QMessageBox::information(this, "Нормалізація", "Усі вузли відновлено до штатного режиму функціонування (Online).");
}

// ----------------- ФАЙЛОВІ ОПЕРАЦІЇ -----------------
void MainWindow::onOpenFile() {
    QString path = QFileDialog::getOpenFileName(this, "Відкрити конфігурацію інфраструктури", "", "JSON Files (*.json);;All Files (*)");
    if (path.isEmpty()) return;

    try {
        m_container.loadFromFile(path);
        m_currentFilePath = path;
        refreshNodesTable();
        refreshIncidentsTable();
        updateStatusBar();
        QMessageBox::information(this, "Успіх", "Дані інфраструктури та інцидентів успішно завантажено!");
    } catch (const MonitoringException& e) {
        QMessageBox::critical(this, "Помилка відкриття", e.what());
    }
}

void MainWindow::onSaveFile() {
    QString path = m_currentFilePath;
    if (path.isEmpty()) {
        path = QFileDialog::getSaveFileName(this, "Зберегти конфігурацію", "infrastructure.json", "JSON Files (*.json)");
    }
    if (path.isEmpty()) return;

    try {
        m_container.saveToFile(path);
        m_currentFilePath = path;
        updateStatusBar();
        QMessageBox::information(this, "Успіх", "Дані збережено у файл:\n" + path);
    } catch (const MonitoringException& e) {
        QMessageBox::critical(this, "Помилка збереження", e.what());
    }
}

void MainWindow::onExportReport() {
    QString path = QFileDialog::getSaveFileName(this, "Експорт звіту інцидентів", "soc_security_report.txt", "Text Files (*.txt)");
    if (path.isEmpty()) return;

    try {
        m_container.exportIncidentReport(path);
        QMessageBox::information(this, "Експорт завершено", "Звіт успішно збережено за шляхом:\n" + path);
    } catch (const MonitoringException& e) {
        QMessageBox::critical(this, "Помилка експорту", e.what());
    }
}

void MainWindow::onLoadSampleData() {
    m_container.loadSampleInfrastructure();
    refreshNodesTable();
    refreshIncidentsTable();
    updateStatusBar();
    if (m_nodesTable->rowCount() > 0) {
        m_nodesTable->selectRow(0);
    }
}

void MainWindow::onTelemetryHeartbeat() {
    // Реалістичне мікро-коливання метрик для серверів
    for (auto& node : m_container.nodes()) {
        if (!node) continue;
        if (node->status() == NodeStatus::Offline) {
            // Сервер аварійно зупинено або знеструмлено — показники нульові та статичні
            continue;
        }

        if (node->status() == NodeStatus::Critical) {
            // Критичний стан: сервер перевантажений (атака або вичерпання ресурсів)
            // Утримуємо напружене коливання у піковій зоні (91% - 99.5%), щоб статус не падав довільно
            double deltaCpu = ((rand() % 31) - 15) / 10.0; // від -1.5% до +1.5%
            double newCpu = std::clamp(node->cpuUsage() + deltaCpu, 91.0, 99.5);
            node->setCpuUsage(newCpu);

            double deltaRam = ((rand() % 21) - 10) / 10.0; // від -1.0% до +1.0%
            double newRam = std::clamp(node->ramUsage() + deltaRam, 92.5, 99.0);
            node->setRamUsage(newRam);
        } else if (node->status() == NodeStatus::Warning) {
            // Підвищене навантаження: коливання у зоні попередження (68% - 85%)
            double deltaCpu = ((rand() % 31) - 15) / 10.0;
            double newCpu = std::clamp(node->cpuUsage() + deltaCpu, 68.0, 85.0);
            node->setCpuUsage(newCpu);

            double deltaRam = ((rand() % 21) - 10) / 10.0;
            double newRam = std::clamp(node->ramUsage() + deltaRam, 72.0, 86.0);
            node->setRamUsage(newRam);
        } else {
            // Нормальний робочий стан (Online): стабільна помірна робота (10% - 65%)
            double deltaCpu = ((rand() % 31) - 15) / 10.0;
            double newCpu = std::clamp(node->cpuUsage() + deltaCpu, 10.0, 65.0);
            node->setCpuUsage(newCpu);

            double deltaRam = ((rand() % 21) - 10) / 10.0;
            double newRam = std::clamp(node->ramUsage() + deltaRam, 15.0, 70.0);
            node->setRamUsage(newRam);
        }
    }

    // Оновлення тексту комірок у таблиці вузлів (навантаження + актуальний статус)
    for (int r = 0; r < m_nodesTable->rowCount(); ++r) {
        auto* idItem = m_nodesTable->item(r, 0);
        if (!idItem) continue;
        int id = idItem->text().toInt();
        auto node = m_container.findNodeById(id);
        if (!node) continue;

        auto* loadItem = m_nodesTable->item(r, 5);
        if (loadItem) {
            loadItem->setText(QString("CPU: %1% | RAM: %2%")
                .arg(node->cpuUsage(), 0, 'f', 1)
                .arg(node->ramUsage(), 0, 'f', 1));
        }

        auto* statusItem = m_nodesTable->item(r, 6);
        if (statusItem) {
            statusItem->setText(node->statusString());
            if (node->status() == NodeStatus::Online) {
                statusItem->setForeground(QColor("#15803d"));
            } else if (node->status() == NodeStatus::Warning) {
                statusItem->setForeground(QColor("#b45309"));
            } else if (node->status() == NodeStatus::Critical) {
                statusItem->setForeground(QColor("#b91c1c"));
            } else {
                statusItem->setForeground(QColor("#64748b"));
            }
        }
    }

    // Якщо активна вкладка флоту або симулятора, оновлюємо шкали виділеного сервера в бічній панелі
    if (m_tabWidget->currentIndex() == 0 || m_tabWidget->currentIndex() == 2) {
        int row = m_nodesTable->currentRow();
        if (row >= 0 && row < m_nodesTable->rowCount()) {
            int nodeId = m_nodesTable->item(row, 0)->text().toInt();
            auto node = m_container.findNodeById(nodeId);
            if (node) {
                double cpu = node->cpuUsage();
                double ram = node->ramUsage();
                m_cpuLabel->setText(QString("Навантаження CPU: %1%").arg(cpu, 0, 'f', 1));
                m_cpuBar->setValue(static_cast<int>(std::clamp(cpu, 0.0, 100.0)));
                QString cpuColor = (cpu >= 85.0) ? "#EF4444" : ((cpu >= 65.0) ? "#F59E0B" : "#3B82F6");
                m_cpuBar->setStyleSheet(QString(R"(
                    QProgressBar { background-color: #E2E8F0; border: 1px solid #CBD5E1; border-radius: 4px; }
                    QProgressBar::chunk { background-color: %1; border-radius: 3px; }
                )").arg(cpuColor));

                m_ramLabel->setText(QString("Використання RAM: %1%").arg(ram, 0, 'f', 1));
                m_ramBar->setValue(static_cast<int>(std::clamp(ram, 0.0, 100.0)));
                QString ramColor = (ram >= 85.0) ? "#EF4444" : ((ram >= 70.0) ? "#F59E0B" : "#10B981");
                m_ramBar->setStyleSheet(QString(R"(
                    QProgressBar { background-color: #E2E8F0; border: 1px solid #CBD5E1; border-radius: 4px; }
                    QProgressBar::chunk { background-color: %1; border-radius: 3px; }
                )").arg(ramColor));
            }
        }
    }

    updateStatusBar();
}
