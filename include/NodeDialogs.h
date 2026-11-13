#pragma once

#include <QDialog>
#include <QLineEdit>
#include <QComboBox>
#include <QDoubleSpinBox>
#include <QSpinBox>
#include <QCheckBox>
#include <QTextEdit>
#include <QStackedWidget>
#include <memory>
#include "InfrastructureNode.h"
#include "SpecificNodes.h"
#include "SecurityIncident.h"

// Діалогове вікно створення та конфігурації нового інфраструктурного вузла
class AddNodeDialog : public QDialog {
    Q_OBJECT

public:
    explicit AddNodeDialog(QWidget* parent = nullptr, int suggestedId = 101);

    std::shared_ptr<InfrastructureNode> getCreatedNode() const;

private slots:
    void onTypeChanged(int index);
    void onAccept();

private:
    void setupUi();

    std::shared_ptr<InfrastructureNode> m_createdNode;

    QComboBox* m_typeCombo;
    QSpinBox* m_idSpin;
    QLineEdit* m_nameEdit;
    QLineEdit* m_ipEdit;
    QLineEdit* m_locationEdit;
    QDoubleSpinBox* m_cpuSpin;
    QDoubleSpinBox* m_ramSpin;

    // Специфічні віджети для типів вузлів
    QStackedWidget* m_typeStack;

    // 1. Server
    QLineEdit* m_srvOsEdit;
    QSpinBox* m_srvServicesSpin;
    QDoubleSpinBox* m_srvDiskSpin;
    QSpinBox* m_srvSshPortSpin;

    // 2. Database
    QLineEdit* m_dbEngineEdit;
    QDoubleSpinBox* m_dbQpsSpin;
    QSpinBox* m_dbConnsSpin;
    QDoubleSpinBox* m_dbStorageSpin;

    // 3. Gateway
    QDoubleSpinBox* m_gwBandwidthSpin;
    QDoubleSpinBox* m_gwDropRateSpin;
    QCheckBox* m_gwFirewallCheck;
    QSpinBox* m_gwBlockedSpin;
};

// Діалогове вікно розслідування та розв'язання інциденту кібербезпеки
class ResolveIncidentDialog : public QDialog {
    Q_OBJECT

public:
    explicit ResolveIncidentDialog(const std::shared_ptr<SecurityIncident>& incident, QWidget* parent = nullptr);

    QString getResolutionNotes() const;
    bool shouldBlockIp() const;

private slots:
    void onAccept();

private:
    void setupUi();

    std::shared_ptr<SecurityIncident> m_incident;
    QTextEdit* m_notesEdit;
    QCheckBox* m_blockIpCheck;
};
