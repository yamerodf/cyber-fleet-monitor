#pragma once

#include <QString>
#include <QDateTime>
#include <QJsonObject>
#include <memory>
#include <iostream>

// Рівні критичності інциденту кібербезпеки
enum class IncidentSeverity {
    Low,
    Medium,
    High,
    Critical
};

// Статуси обробки інциденту
enum class IncidentStatus {
    New,
    InProgress,
    Mitigated,
    Resolved
};

// Базовий абстрактний клас події/інциденту інформаційної безпеки
class SecurityIncident {
public:
    SecurityIncident(int id, int targetNodeId, QString targetNodeName,
                     QString sourceIp, IncidentSeverity severity, QString description);
    virtual ~SecurityIncident() = default;

    // Rule of 5
    SecurityIncident(const SecurityIncident&) = delete;
    SecurityIncident& operator=(const SecurityIncident&) = delete;
    SecurityIncident(SecurityIncident&&) noexcept = default;
    SecurityIncident& operator=(SecurityIncident&&) noexcept = default;

    // Гетери та сетери
    int id() const { return m_id; }
    void setId(int id) { m_id = id; }

    int targetNodeId() const { return m_targetNodeId; }
    void setTargetNodeId(int nodeId) { m_targetNodeId = nodeId; }

    const QString& targetNodeName() const { return m_targetNodeName; }
    void setTargetNodeName(const QString& name);

    const QDateTime& timestamp() const { return m_timestamp; }
    void setTimestamp(const QDateTime& dt) { m_timestamp = dt; }

    const QString& sourceIp() const { return m_sourceIp; }
    void setSourceIp(const QString& ip);

    IncidentSeverity severity() const { return m_severity; }
    void setSeverity(IncidentSeverity sev) { m_severity = sev; }
    QString severityString() const;

    IncidentStatus status() const { return m_status; }
    void setStatus(IncidentStatus st) { m_status = st; }
    QString statusString() const;

    const QString& description() const { return m_description; }
    void setDescription(const QString& desc);

    const QString& resolutionNotes() const { return m_resolutionNotes; }
    void setResolutionNotes(const QString& notes);

    // Чисто віртуальний інтерфейс
    virtual QString categoryName() const = 0;
    virtual QString getMitigationPlan() const = 0;
    virtual std::shared_ptr<SecurityIncident> clone() const = 0;
    virtual QJsonObject toJson() const = 0;
    virtual void fromJson(const QJsonObject& json) = 0;

    // Операція вирішення інциденту
    void resolve(const QString& notes);

    // Перевантажені оператори
    virtual bool operator<(const SecurityIncident& other) const;
    virtual bool operator==(const SecurityIncident& other) const;
    bool operator!=(const SecurityIncident& other) const;

    friend std::ostream& operator<<(std::ostream& os, const SecurityIncident& inc);

protected:
    virtual void printDetails(std::ostream& os) const;

    int m_id;
    int m_targetNodeId;
    QString m_targetNodeName;
    QDateTime m_timestamp;
    QString m_sourceIp;
    IncidentSeverity m_severity;
    IncidentStatus m_status;
    QString m_description;
    QString m_resolutionNotes;
};
