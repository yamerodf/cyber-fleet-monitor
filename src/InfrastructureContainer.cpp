#include "InfrastructureContainer.h"
#include "MonitoringExceptions.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <QTextStream>
#include <algorithm>
#include <numeric>

// Конструктор ініціалізує початкову стратегію
InfrastructureContainer::InfrastructureContainer()
    : m_strategy(std::make_unique<ThresholdAnalysisStrategy>()),
      m_nextNodeId(101),
      m_nextIncidentId(1) {}

// Додавання вузла з контролем унікальності IP та ID
void InfrastructureContainer::addNode(std::shared_ptr<InfrastructureNode> node) {
    if (!node) {
        throw ValidationException("Неможливо додати порожній об'єкт вузла.");
    }

    for (const auto& existing : m_nodes) {
        if (existing->id() == node->id()) {
            throw DuplicateNodeException("Вузол з ID " + std::to_string(node->id()) + " вже існує.");
        }
        if (existing->ipAddress().compare(node->ipAddress(), Qt::CaseInsensitive) == 0) {
            throw DuplicateNodeException("IP-адреса " + node->ipAddress().toStdString() + " вже зайнята іншим вузлом.");
        }
    }

    if (node->id() >= m_nextNodeId) {
        m_nextNodeId = node->id() + 1;
    }
    m_nodes.push_back(std::move(node));
}

// Видалення вузла за ID
bool InfrastructureContainer::removeNode(int id) {
    auto it = std::find_if(m_nodes.begin(), m_nodes.end(), [id](const std::shared_ptr<InfrastructureNode>& n) {
        return n->id() == id;
    });
    if (it != m_nodes.end()) {
        m_nodes.erase(it);
        return true;
    }
    return false;
}

// Пошук вузла за ID
std::shared_ptr<InfrastructureNode> InfrastructureContainer::findNodeById(int id) const {
    auto it = std::find_if(m_nodes.begin(), m_nodes.end(), [id](const std::shared_ptr<InfrastructureNode>& n) {
        return n->id() == id;
    });
    return (it != m_nodes.end()) ? *it : nullptr;
}

// Пошук вузла за IP
std::shared_ptr<InfrastructureNode> InfrastructureContainer::findNodeByIp(const QString& ip) const {
    auto it = std::find_if(m_nodes.begin(), m_nodes.end(), [&](const std::shared_ptr<InfrastructureNode>& n) {
        return n->ipAddress().compare(ip.trimmed(), Qt::CaseInsensitive) == 0;
    });
    return (it != m_nodes.end()) ? *it : nullptr;
}

// Фільтрація вузлів за ім'ям, IP або локацією
std::vector<std::shared_ptr<InfrastructureNode>> InfrastructureContainer::filterNodes(const QString& query) const {
    const QString q = query.trimmed();
    if (q.isEmpty()) return m_nodes;

    std::vector<std::shared_ptr<InfrastructureNode>> result;
    for (const auto& node : m_nodes) {
        if (node->name().contains(q, Qt::CaseInsensitive) ||
            node->ipAddress().contains(q, Qt::CaseInsensitive) ||
            node->location().contains(q, Qt::CaseInsensitive) ||
            node->typeName().contains(q, Qt::CaseInsensitive)) {
            result.push_back(node);
        }
    }
    return result;
}

void InfrastructureContainer::clearNodes() {
    m_nodes.clear();
}

// Додавання інциденту безпеки
void InfrastructureContainer::addIncident(std::shared_ptr<SecurityIncident> incident) {
    if (!incident) {
        throw ValidationException("Помилка реєстрації інциденту: об'єкт відсутній.");
    }
    if (incident->id() >= m_nextIncidentId) {
        m_nextIncidentId = incident->id() + 1;
    }
    m_incidents.push_back(std::move(incident));
}

// Вирішення інциденту з фіксацією коментаря
bool InfrastructureContainer::resolveIncident(int id, const QString& notes) {
    auto it = std::find_if(m_incidents.begin(), m_incidents.end(), [id](const std::shared_ptr<SecurityIncident>& inc) {
        return inc->id() == id;
    });
    if (it != m_incidents.end()) {
        (*it)->resolve(notes);
        return true;
    }
    return false;
}

// Пошук інциденту за ID
std::shared_ptr<SecurityIncident> InfrastructureContainer::findIncidentById(int id) const {
    auto it = std::find_if(m_incidents.begin(), m_incidents.end(), [id](const std::shared_ptr<SecurityIncident>& inc) {
        return inc->id() == id;
    });
    return (it != m_incidents.end()) ? *it : nullptr;
}

// Фільтрація інцидентів за ключовим словом
std::vector<std::shared_ptr<SecurityIncident>> InfrastructureContainer::filterIncidents(const QString& query) const {
    const QString q = query.trimmed();
    if (q.isEmpty()) return m_incidents;

    std::vector<std::shared_ptr<SecurityIncident>> result;
    for (const auto& inc : m_incidents) {
        if (inc->targetNodeName().contains(q, Qt::CaseInsensitive) ||
            inc->sourceIp().contains(q, Qt::CaseInsensitive) ||
            inc->categoryName().contains(q, Qt::CaseInsensitive) ||
            inc->description().contains(q, Qt::CaseInsensitive)) {
            result.push_back(inc);
        }
    }
    return result;
}

void InfrastructureContainer::clearIncidents() {
    m_incidents.clear();
}

// Зміна поточної стратегії аудиту
void InfrastructureContainer::setStrategy(std::unique_ptr<IAnalysisStrategy> strategy) {
    if (strategy) {
        m_strategy = std::move(strategy);
    }
}

// Запуск аналізу безпеки обраною стратегією
int InfrastructureContainer::runSecurityAudit() {
    if (!m_strategy) return 0;
    auto newIncidents = m_strategy->analyze(m_nodes, m_nextIncidentId);
    int addedCount = 0;
    for (auto& inc : newIncidents) {
        m_incidents.push_back(std::move(inc));
        ++addedCount;
    }
    return addedCount;
}

// Кількість вузлів онлайн
int InfrastructureContainer::onlineNodes() const {
    return std::count_if(m_nodes.begin(), m_nodes.end(), [](const std::shared_ptr<InfrastructureNode>& n) {
        return n->status() == NodeStatus::Online || n->status() == NodeStatus::Warning;
    });
}

// Кількість вузлів у критичному стані
int InfrastructureContainer::criticalNodes() const {
    return std::count_if(m_nodes.begin(), m_nodes.end(), [](const std::shared_ptr<InfrastructureNode>& n) {
        return n->status() == NodeStatus::Critical || n->status() == NodeStatus::Offline;
    });
}

// Кількість активних (невирішених) інцидентів
int InfrastructureContainer::activeIncidentsCount() const {
    return std::count_if(m_incidents.begin(), m_incidents.end(), [](const std::shared_ptr<SecurityIncident>& inc) {
        return inc->status() != IncidentStatus::Resolved;
    });
}

// Сортування вузлів за первинною метрикою навантаження (std::sort з ЛР 2.1)
void InfrastructureContainer::sortNodesByMetric(bool ascending) {
    std::sort(m_nodes.begin(), m_nodes.end(), [ascending](const std::shared_ptr<InfrastructureNode>& a, const std::shared_ptr<InfrastructureNode>& b) {
        return ascending ? (a->getPrimaryMetric() < b->getPrimaryMetric())
                         : (a->getPrimaryMetric() > b->getPrimaryMetric());
    });
}

// Сортування вузлів за алфавітною назвою (std::sort з ЛР 2.1)
void InfrastructureContainer::sortNodesByName(bool ascending) {
    std::sort(m_nodes.begin(), m_nodes.end(), [ascending](const std::shared_ptr<InfrastructureNode>& a, const std::shared_ptr<InfrastructureNode>& b) {
        return ascending ? (a->name() < b->name())
                         : (a->name() > b->name());
    });
}

// Середнє навантаження на процесори інфраструктури (шаблонний метод)
double InfrastructureContainer::averageCpuUsage() const {
    return aggregateNodeMetric([](const std::shared_ptr<InfrastructureNode>& n) {
        return n->cpuUsage();
    });
}

// Середнє використання оперативної пам'яті (шаблонний метод)
double InfrastructureContainer::averageRamUsage() const {
    return aggregateNodeMetric([](const std::shared_ptr<InfrastructureNode>& n) {
        return n->ramUsage();
    });
}

// Збереження інфраструктури та інцидентів у JSON файл
void InfrastructureContainer::saveToFile(const QString& filePath) const {
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        throw StorageIOException("Не вдалося відкрити файл для запису: " + filePath.toStdString());
    }

    QJsonObject root;
    QJsonArray nodesArray;
    for (const auto& node : m_nodes) {
        nodesArray.append(node->toJson());
    }
    root["nodes"] = nodesArray;

    QJsonArray incidentsArray;
    for (const auto& inc : m_incidents) {
        incidentsArray.append(inc->toJson());
    }
    root["incidents"] = incidentsArray;

    QJsonDocument doc(root);
    file.write(doc.toJson(QJsonDocument::Indented));
    file.close();
}

// Завантаження інфраструктури з JSON файлу
void InfrastructureContainer::loadFromFile(const QString& filePath) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        throw StorageIOException("Не вдалося відкрити файл для читання: " + filePath.toStdString());
    }

    QByteArray data = file.readAll();
    file.close();

    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(data, &parseError);
    if (parseError.error != QJsonParseError::NoError) {
        throw StorageIOException("Помилка парсингу JSON: " + parseError.errorString().toStdString());
    }

    QJsonObject root = doc.object();
    m_nodes.clear();
    m_incidents.clear();

    // Завантаження вузлів
    QJsonArray nodesArray = root["nodes"].toArray();
    for (const auto& val : nodesArray) {
        QJsonObject obj = val.toObject();
        QString type = obj["type"].toString();
        std::shared_ptr<InfrastructureNode> node;

        if (type == "GenericServer") {
            node = std::make_shared<ServerNode>(0, "temp-node", "0.0.0.0", "default");
        } else if (type == "DatabaseCluster") {
            node = std::make_shared<DatabaseNode>(0, "temp-node", "0.0.0.0", "default");
        } else if (type == "NetworkGateway") {
            node = std::make_shared<NetworkGatewayNode>(0, "temp-node", "0.0.0.0", "default");
        }

        if (node) {
            node->fromJson(obj);
            if (node->id() >= m_nextNodeId) m_nextNodeId = node->id() + 1;
            m_nodes.push_back(node);
        }
    }

    // Завантаження інцидентів
    QJsonArray incidentsArray = root["incidents"].toArray();
    for (const auto& val : incidentsArray) {
        QJsonObject obj = val.toObject();
        QString type = obj["type"].toString();
        std::shared_ptr<SecurityIncident> inc;

        if (type == "BruteForceIncident") {
            inc = std::make_shared<BruteForceIncident>(0, 0, "temp-target", "127.0.0.1", IncidentSeverity::Medium, "desc");
        } else if (type == "DDoSAnomalyIncident") {
            inc = std::make_shared<DDoSAnomalyIncident>(0, 0, "temp-target", "127.0.0.1", IncidentSeverity::High, "desc");
        } else if (type == "ResourceSpikeIncident") {
            inc = std::make_shared<ResourceSpikeIncident>(0, 0, "temp-target", "127.0.0.1", IncidentSeverity::High, "desc");
        } else if (type == "UnauthorizedAccessIncident") {
            inc = std::make_shared<UnauthorizedAccessIncident>(0, 0, "temp-target", "127.0.0.1", IncidentSeverity::Critical, "desc");
        }

        if (inc) {
            inc->fromJson(obj);
            if (inc->id() >= m_nextIncidentId) m_nextIncidentId = inc->id() + 1;
            m_incidents.push_back(inc);
        }
    }
}

// Експорт текстового звіту аудиту інфраструктури
void InfrastructureContainer::exportIncidentReport(const QString& filePath) const {
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        throw StorageIOException("Не вдалося створити звіт: " + filePath.toStdString());
    }

    QTextStream out(&file);
    out << "======================================================================\n";
    out << "      СИТУАЦІЙНИЙ ЗВІТ ЦЕНТРУ КІБЕРБЕЗПЕКИ ТА ДЕВОПС-МОНІТОРИНГУ      \n";
    out << "======================================================================\n\n";
    out << QString("Загальна кількість серверних вузлів:  %1\n").arg(totalNodes());
    out << QString("Активні сервери онлайн:                %1\n").arg(onlineNodes());
    out << QString("Вузли у критичному стані:              %1\n").arg(criticalNodes());
    out << QString("Загальна кількість інцидентів SOC:     %1\n").arg(m_incidents.size());
    out << QString("Активні невирішені загрози:            %1\n").arg(activeIncidentsCount());
    out << QString("Середнє навантаження CPU по парку:     %1%\n").arg(averageCpuUsage(), 0, 'f', 1);
    out << QString("Середнє використання RAM:              %1%\n\n").arg(averageRamUsage(), 0, 'f', 1);
    out << "----------------------------------------------------------------------\n";
    out << "СТАН ІНФРАСТРУКТУРНИХ ВУЗЛІВ:\n";

    for (const auto& node : m_nodes) {
        out << QString("  [%1] ID:%2 | %3 (%4)\n")
                   .arg(node->typeName()).arg(node->id()).arg(node->name()).arg(node->ipAddress());
        out << QString("      Локація: %1 | Статус: %2 | CPU: %3% | RAM: %4% | Uptime: %5h\n")
                   .arg(node->location()).arg(node->statusString())
                   .arg(node->cpuUsage(), 0, 'f', 1).arg(node->ramUsage(), 0, 'f', 1)
                   .arg(node->uptimeHours());
        out << QString("      Телеметрія: %1\n\n").arg(node->getHealthSummary());
    }

    out << "----------------------------------------------------------------------\n";
    out << "ЖУРНАЛ ЗАГРОЗ ТА АНОМАЛІЙ БЕЗПЕКИ:\n";

    for (const auto& inc : m_incidents) {
        out << QString("  [#%1] %2 — %3\n").arg(inc->id()).arg(inc->categoryName()).arg(inc->severityString());
        out << QString("      Ціль: %1 | Джерело атаки: %2 | Час: %3\n")
                   .arg(inc->targetNodeName()).arg(inc->sourceIp())
                   .arg(inc->timestamp().toString("dd.MM.yyyy hh:mm:ss"));
        out << QString("      Опис: %1\n").arg(inc->description());
        out << QString("      Статус реагування: %1\n").arg(inc->statusString());
        if (!inc->resolutionNotes().isEmpty()) {
            out << QString("      Заходи вирішення: %1\n").arg(inc->resolutionNotes());
        }
        out << "\n";
    }

    out << "======================================================================\n";
    file.close();
}

// Завантаження зразкової промислової інфраструктури
void InfrastructureContainer::loadSampleInfrastructure() {
    clearNodes();
    clearIncidents();
    m_nextNodeId = 101;
    m_nextIncidentId = 1;

    // 1. Головний веб-сервер API
    auto srv1 = std::make_shared<ServerNode>(
        101, "prod-api-eu-central", "192.168.10.15", "Франкфурт (AWS eu-central-1)",
        "Ubuntu 24.04 LTS", 14, 42.5, 2222
    );
    srv1->setCpuUsage(34.2);
    srv1->setRamUsage(61.8);
    srv1->setUptimeHours(720);
    srv1->updateHealthStatus();
    addNode(srv1);

    // 2. Кластер основної бази даних PostgreSQL
    auto db1 = std::make_shared<DatabaseNode>(
        102, "pg-cluster-primary", "192.168.10.20", "Франкфурт (AWS eu-central-1)",
        "PostgreSQL 16 High-Availability", 1240.0, 142, 680.0
    );
    db1->setCpuUsage(58.4);
    db1->setRamUsage(74.0);
    db1->setUptimeHours(1440);
    db1->updateHealthStatus();
    addNode(db1);

    // 3. Мережевий шлюз та прикордонний фаєрвол
    auto gw1 = std::make_shared<NetworkGatewayNode>(
        103, "border-edge-firewall", "192.168.10.1", "Франкфурт (Edge Router)",
        480.0, 0.04, true, 28
    );
    gw1->setCpuUsage(18.5);
    gw1->setRamUsage(31.2);
    gw1->setUptimeHours(2160);
    gw1->updateHealthStatus();
    addNode(gw1);

    // 4. Аналітичний воркер (підвищене навантаження)
    auto srv2 = std::make_shared<ServerNode>(
        104, "analytics-worker-01", "192.168.10.35", "Варшава (DC Equinix)",
        "Debian 12 Bookworm", 6, 88.2, 22
    );
    srv2->setCpuUsage(91.5);
    srv2->setRamUsage(94.2);
    srv2->setUptimeHours(340);
    srv2->updateHealthStatus();
    addNode(srv2);

    // 5. Тестовий інцидент 1: Brute-Force на шлюз
    auto inc1 = std::make_shared<BruteForceIncident>(
        m_nextIncidentId++, gw1->id(), gw1->name(), "185.220.101.5",
        IncidentSeverity::High,
        "Масований підбір паролів до порту управління SSH (виявлено 184 невдалих спроби).",
        184, "SSH Edge Interface");
    addIncident(inc1);

    // 2. Тестовий інцидент 2: Критичне вичерпання пам'яті на воркері
    auto inc2 = std::make_shared<ResourceSpikeIncident>(
        m_nextIncidentId++, srv2->id(), srv2->name(), "127.0.0.1",
        IncidentSeverity::Critical,
        "Аналітичний процес зайняв 94.2% оперативної пам'яті. Високий ризик примусового завершення системи OOM-Killer.",
        "RAM Usage", 94.2, "spark-worker-batch [PID 9042]");
    addIncident(inc2);
}
