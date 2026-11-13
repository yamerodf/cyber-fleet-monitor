#include "NodeDialogs.h"
#include <QFormLayout>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QMessageBox>
#include <QAbstractButton>

// ============================================================================
// AddNodeDialog
// ============================================================================
AddNodeDialog::AddNodeDialog(QWidget* parent, int suggestedId)
    : QDialog(parent) {
    setWindowTitle("Додати новий вузол інфраструктури");
    resize(500, 480);
    setupUi();
    m_idSpin->setValue(suggestedId);
}

void AddNodeDialog::setupUi() {
    auto* mainLayout = new QVBoxLayout(this);
    auto* formLayout = new QFormLayout();

    m_typeCombo = new QComboBox(this);
    m_typeCombo->addItems({"Обчислювальний сервер (Compute Server)",
                           "Кластер баз даних (Database Cluster)",
                           "Мережевий шлюз / Firewall (Security Gateway)"});

    m_idSpin = new QSpinBox(this);
    m_idSpin->setRange(1, 999999);

    m_nameEdit = new QLineEdit(this);
    m_nameEdit->setPlaceholderText("Наприклад: prod-backend-02");

    m_ipEdit = new QLineEdit(this);
    m_ipEdit->setPlaceholderText("Наприклад: 192.168.10.50");

    m_locationEdit = new QLineEdit(this);
    m_locationEdit->setText("Франкфурт (AWS eu-central-1)");

    m_cpuSpin = new QDoubleSpinBox(this);
    m_cpuSpin->setRange(0.0, 1000.0);
    m_cpuSpin->setValue(20.0);
    m_cpuSpin->setSuffix(" %");

    m_ramSpin = new QDoubleSpinBox(this);
    m_ramSpin->setRange(0.0, 1000.0);
    m_ramSpin->setValue(35.0);
    m_ramSpin->setSuffix(" %");

    formLayout->addRow("Тип вузла:", m_typeCombo);
    formLayout->addRow("ID вузла:", m_idSpin);
    formLayout->addRow("Назва вузла:", m_nameEdit);
    formLayout->addRow("IP-адреса:", m_ipEdit);
    formLayout->addRow("Локація / ДЦ:", m_locationEdit);
    formLayout->addRow("Початковий CPU:", m_cpuSpin);
    formLayout->addRow("Початковий RAM:", m_ramSpin);

    mainLayout->addLayout(formLayout);

    // Специфічні блоки
    m_typeStack = new QStackedWidget(this);

    // 1. Server Page
    auto* srvWidget = new QWidget(this);
    auto* srvLayout = new QFormLayout(srvWidget);
    m_srvOsEdit = new QLineEdit("Ubuntu 24.04 LTS", this);
    m_srvServicesSpin = new QSpinBox(this);
    m_srvServicesSpin->setValue(8);
    m_srvDiskSpin = new QDoubleSpinBox(this);
    m_srvDiskSpin->setRange(0.0, 100.0);
    m_srvDiskSpin->setValue(40.0);
    m_srvDiskSpin->setSuffix(" %");
    m_srvSshPortSpin = new QSpinBox(this);
    m_srvSshPortSpin->setRange(1, 65535);
    m_srvSshPortSpin->setValue(22);
    srvLayout->addRow("Версія ОС:", m_srvOsEdit);
    srvLayout->addRow("Активних служб:", m_srvServicesSpin);
    srvLayout->addRow("Використання диска:", m_srvDiskSpin);
    srvLayout->addRow("Порт SSH:", m_srvSshPortSpin);
    m_typeStack->addWidget(srvWidget);

    // 2. Database Page
    auto* dbWidget = new QWidget(this);
    auto* dbLayout = new QFormLayout(dbWidget);
    m_dbEngineEdit = new QLineEdit("PostgreSQL 16", this);
    m_dbQpsSpin = new QDoubleSpinBox(this);
    m_dbQpsSpin->setRange(0.0, 100000.0);
    m_dbQpsSpin->setValue(500.0);
    m_dbConnsSpin = new QSpinBox(this);
    m_dbConnsSpin->setRange(0, 10000);
    m_dbConnsSpin->setValue(50);
    m_dbStorageSpin = new QDoubleSpinBox(this);
    m_dbStorageSpin->setRange(0.0, 100000.0);
    m_dbStorageSpin->setValue(100.0);
    m_dbStorageSpin->setSuffix(" GB");
    dbLayout->addRow("Рушій СУБД:", m_dbEngineEdit);
    dbLayout->addRow("Запитів/сек (QPS):", m_dbQpsSpin);
    dbLayout->addRow("Активних з'єднань:", m_dbConnsSpin);
    dbLayout->addRow("Розмір сховища:", m_dbStorageSpin);
    m_typeStack->addWidget(dbWidget);

    // 3. Gateway Page
    auto* gwWidget = new QWidget(this);
    auto* gwLayout = new QFormLayout(gwWidget);
    m_gwBandwidthSpin = new QDoubleSpinBox(this);
    m_gwBandwidthSpin->setRange(0.0, 100000.0);
    m_gwBandwidthSpin->setValue(300.0);
    m_gwBandwidthSpin->setSuffix(" Mbps");
    m_gwDropRateSpin = new QDoubleSpinBox(this);
    m_gwDropRateSpin->setRange(0.0, 100.0);
    m_gwDropRateSpin->setValue(0.01);
    m_gwDropRateSpin->setSuffix(" %");
    m_gwFirewallCheck = new QCheckBox("Активовано фаєрвол (Stateful Inspection)", this);
    m_gwFirewallCheck->setChecked(true);
    m_gwBlockedSpin = new QSpinBox(this);
    m_gwBlockedSpin->setValue(5);
    gwLayout->addRow("Пропускна здатність:", m_gwBandwidthSpin);
    gwLayout->addRow("Втрата пакетів:", m_gwDropRateSpin);
    gwLayout->addRow("Захист:", m_gwFirewallCheck);
    gwLayout->addRow("Заблоковано IP:", m_gwBlockedSpin);
    m_typeStack->addWidget(gwWidget);

    mainLayout->addWidget(m_typeStack);

    connect(m_typeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &AddNodeDialog::onTypeChanged);

    // Кнопки дій
    auto* btnLayout = new QHBoxLayout();
    auto* okBtn = new QPushButton("Створити вузол", this);
    auto* cancelBtn = new QPushButton("Скасувати", this);
    okBtn->setDefault(true);

    connect(okBtn, &QPushButton::clicked, this, &AddNodeDialog::onAccept);
    connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);

    btnLayout->addStretch();
    btnLayout->addWidget(cancelBtn);
    btnLayout->addWidget(okBtn);

    mainLayout->addLayout(btnLayout);

    for (auto* btn : findChildren<QAbstractButton*>()) {
        btn->setCursor(Qt::PointingHandCursor);
    }
}

void AddNodeDialog::onTypeChanged(int index) {
    m_typeStack->setCurrentIndex(index);
}

void AddNodeDialog::onAccept() {
    if (m_nameEdit->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, "Помилка валідації", "Назва вузла обов'язкова для заповнення!");
        m_nameEdit->setFocus();
        return;
    }
    if (m_ipEdit->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, "Помилка валідації", "IP-адреса обов'язкова!");
        m_ipEdit->setFocus();
        return;
    }

    int typeIdx = m_typeCombo->currentIndex();
    if (typeIdx == 0) {
        auto srv = std::make_shared<ServerNode>(
            m_idSpin->value(), m_nameEdit->text().trimmed(), m_ipEdit->text().trimmed(),
            m_locationEdit->text().trimmed(), m_srvOsEdit->text().trimmed(),
            m_srvServicesSpin->value(), m_srvDiskSpin->value(), m_srvSshPortSpin->value()
        );
        srv->setCpuUsage(m_cpuSpin->value());
        srv->setRamUsage(m_ramSpin->value());
        srv->updateHealthStatus();
        m_createdNode = srv;
    } else if (typeIdx == 1) {
        auto db = std::make_shared<DatabaseNode>(
            m_idSpin->value(), m_nameEdit->text().trimmed(), m_ipEdit->text().trimmed(),
            m_locationEdit->text().trimmed(), m_dbEngineEdit->text().trimmed(),
            m_dbQpsSpin->value(), m_dbConnsSpin->value(), m_dbStorageSpin->value()
        );
        db->setCpuUsage(m_cpuSpin->value());
        db->setRamUsage(m_ramSpin->value());
        db->updateHealthStatus();
        m_createdNode = db;
    } else {
        auto gw = std::make_shared<NetworkGatewayNode>(
            m_idSpin->value(), m_nameEdit->text().trimmed(), m_ipEdit->text().trimmed(),
            m_locationEdit->text().trimmed(), m_gwBandwidthSpin->value(),
            m_gwDropRateSpin->value(), m_gwFirewallCheck->isChecked(), m_gwBlockedSpin->value()
        );
        gw->setCpuUsage(m_cpuSpin->value());
        gw->setRamUsage(m_ramSpin->value());
        gw->updateHealthStatus();
        m_createdNode = gw;
    }

    accept();
}

std::shared_ptr<InfrastructureNode> AddNodeDialog::getCreatedNode() const {
    return m_createdNode;
}

// ============================================================================
// ResolveIncidentDialog
// ============================================================================
ResolveIncidentDialog::ResolveIncidentDialog(const std::shared_ptr<SecurityIncident>& incident, QWidget* parent)
    : QDialog(parent), m_incident(incident) {
    setWindowTitle(QString("Розслідування інциденту #%1 [%2]").arg(m_incident->id()).arg(m_incident->categoryName()));
    resize(480, 360);
    setupUi();
}

void ResolveIncidentDialog::setupUi() {
    auto* mainLayout = new QVBoxLayout(this);

    auto* headerLabel = new QLabel(
        QString("<b>Інцидент:</b> %1<br>"
                "<b>Цільовий вузол:</b> %2 | <b>Джерело (IP):</b> %3<br>"
                "<b>Критичність:</b> %4<br><br>"
                "<b>Рекомендований план нейтралізації:</b><br><i>%5</i>")
            .arg(m_incident->categoryName())
            .arg(m_incident->targetNodeName())
            .arg(m_incident->sourceIp())
            .arg(m_incident->severityString())
            .arg(m_incident->getMitigationPlan()),
        this
    );
    headerLabel->setStyleSheet("padding: 8px; background-color: #f1f5f9; border-radius: 4px;");
    headerLabel->setWordWrap(true);
    mainLayout->addWidget(headerLabel);

    m_blockIpCheck = new QCheckBox(
        QString("Заблокувати IP %1 на прикордонному фаєрволі (Drop Traffic)").arg(m_incident->sourceIp()), this);
    m_blockIpCheck->setChecked(true);
    mainLayout->addWidget(m_blockIpCheck);

    auto* notesLabel = new QLabel("Заходи реагування та коментар інженера SecOps:", this);
    mainLayout->addWidget(notesLabel);

    m_notesEdit = new QTextEdit(this);
    m_notesEdit->setPlaceholderText("Опишіть вжиті дії (наприклад: IP заблоковано в iptables, сервіс перезапущено)...");
    m_notesEdit->setText("Загрозу локалізовано. Проведено аудит безпеки та оновлено правила фільтрації трафіку.");
    mainLayout->addWidget(m_notesEdit);

    auto* btnLayout = new QHBoxLayout();
    auto* resolveBtn = new QPushButton("Закрити інцидент (Resolve)", this);
    auto* cancelBtn = new QPushButton("Скасувати", this);
    resolveBtn->setDefault(true);

    connect(resolveBtn, &QPushButton::clicked, this, &ResolveIncidentDialog::onAccept);
    connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);

    btnLayout->addStretch();
    btnLayout->addWidget(cancelBtn);
    btnLayout->addWidget(resolveBtn);

    mainLayout->addLayout(btnLayout);

    for (auto* btn : findChildren<QAbstractButton*>()) {
        btn->setCursor(Qt::PointingHandCursor);
    }
}

void ResolveIncidentDialog::onAccept() {
    if (m_notesEdit->toPlainText().trimmed().isEmpty()) {
        QMessageBox::warning(this, "Помилка", "Будь ласка, вкажіть заходи реагування для закриття інциденту!");
        m_notesEdit->setFocus();
        return;
    }
    accept();
}

QString ResolveIncidentDialog::getResolutionNotes() const {
    return m_notesEdit->toPlainText().trimmed();
}

bool ResolveIncidentDialog::shouldBlockIp() const {
    return m_blockIpCheck->isChecked();
}
