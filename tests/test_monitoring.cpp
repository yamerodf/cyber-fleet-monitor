#include <QCoreApplication>
#include <iostream>
#include <sstream>
#include <cassert>
#include <QFile>

#include "MonitoringExceptions.h"
#include "InfrastructureNode.h"
#include "SpecificNodes.h"
#include "SecurityIncident.h"
#include "SpecificIncidents.h"
#include "AnalysisStrategy.h"
#include "InfrastructureContainer.h"

void testNodeHierarchy() {
    std::cout << "[TEST] 1. Ієрархія інфраструктурних вузлів (Server, DB, Gateway)... ";

    auto srv = std::make_shared<ServerNode>(1, "srv-app-01", "10.0.0.5", "Kyiv DC");
    assert(srv->type() == NodeType::GenericServer);
    assert(srv->typeName() == "Compute Server");
    assert(srv->sshPort() == 22);

    auto db = std::make_shared<DatabaseNode>(2, "db-pg-cluster", "10.0.0.10", "Frankfurt DC", "PostgreSQL", 1500.0, 50, 400.0);
    assert(db->type() == NodeType::DatabaseCluster);
    assert(db->queriesPerSecond() == 1500.0);

    auto gw = std::make_shared<NetworkGatewayNode>(3, "gw-edge-fw", "10.0.0.1", "Edge");
    assert(gw->type() == NodeType::NetworkGateway);
    assert(gw->isFirewallActive());

    // Поліморфізм через базовий вказівник
    std::shared_ptr<InfrastructureNode> baseNode = srv;
    assert(baseNode->name() == "srv-app-01");
    auto cloneNode = baseNode->clone();
    assert(cloneNode->id() == srv->id());
    assert(cloneNode->name() == srv->name());

    std::cout << "OK\n";
}

void testIncidentHierarchy() {
    std::cout << "[TEST] 2. Ієрархія інцидентів безпеки та плани нейтралізації... ";

    auto bf = std::make_shared<BruteForceIncident>(1, 101, "srv-app-01", "185.12.34.5", IncidentSeverity::High, "SSH Attack", 120, "SSH");
    assert(bf->failedAttempts() == 120);
    assert(!bf->getMitigationPlan().isEmpty());
    assert(bf->status() == IncidentStatus::New);

    bf->resolve("IP blocked on firewall.");
    assert(bf->status() == IncidentStatus::Resolved);
    assert(bf->resolutionNotes() == "IP blocked on firewall.");

    auto ddos = std::make_shared<DDoSAnomalyIncident>(2, 103, "gw-edge-fw", "45.10.20.30", IncidentSeverity::Critical, "DDoS", 10.5, 500.0, "SYN Flood");
    assert(ddos->trafficSpikeGbps() == 10.5);

    auto spike = std::make_shared<ResourceSpikeIncident>(3, 101, "srv-app-01", "127.0.0.1", IncidentSeverity::High, "High CPU", "CPU", 99.1, "miner-proc");
    assert(spike->metricValue() == 99.1);

    auto breach = std::make_shared<UnauthorizedAccessIncident>(4, 102, "db-pg-cluster", "192.168.1.100", IncidentSeverity::Critical, "Data Leak", "/etc/shadow", 98);
    assert(breach->riskScore() == 98);

    std::cout << "OK\n";
}

void testStrategyPattern() {
    std::cout << "[TEST] 3. Патерн Стратегія (Threshold & Heuristic Strategy)... ";

    std::vector<std::shared_ptr<InfrastructureNode>> nodes;
    auto srv = std::make_shared<ServerNode>(1, "srv-high-load", "10.0.0.2", "Cloud");
    srv->setCpuUsage(95.0); // Перевищення порогу 90%
    nodes.push_back(srv);

    int nextId = 1;
    ThresholdAnalysisStrategy thresholdStrat;
    auto alerts1 = thresholdStrat.analyze(nodes, nextId);
    assert(!alerts1.empty());
    assert(alerts1[0]->severity() == IncidentSeverity::High);

    HeuristicAnomalyStrategy heuristicStrat;
    auto db = std::make_shared<DatabaseNode>(2, "db-abnormal", "10.0.0.3", "Cloud", "PostgreSQL", 4500.0, 5, 200.0);
    nodes.push_back(db);
    auto alerts2 = heuristicStrat.analyze(nodes, nextId);
    assert(!alerts2.empty());

    std::cout << "OK\n";
}

void testContainerOperations() {
    std::cout << "[TEST] 4. Репозиторій-контейнер (CRUD, пошук, фільтрація, статистика)... ";

    InfrastructureContainer container;
    container.loadSampleInfrastructure();

    assert(container.totalNodes() >= 4);
    assert(container.onlineNodes() >= 3);
    assert(container.activeIncidentsCount() >= 2);
    assert(container.averageCpuUsage() > 0.0);

    // Пошук вузла за ID та IP
    auto node = container.findNodeById(101);
    assert(node != nullptr);
    assert(container.findNodeByIp("192.168.10.15") != nullptr);

    // Фільтрація вузлів
    auto filtered = container.filterNodes("postgres");
    assert(filtered.size() == 1);
    assert(filtered[0]->id() == 102);

    // Шаблонна фільтрація за предикатом (ЛР 2.1, 2.2)
    auto highLoadNodes = container.findNodesByPredicate([](const std::shared_ptr<InfrastructureNode>& n) {
        return n->cpuUsage() > 50.0;
    });
    assert(!highLoadNodes.empty());

    // Шаблонна агрегація метрик (ЛР 2.1, 2.2)
    double avgUptime = container.aggregateNodeMetric([](const std::shared_ptr<InfrastructureNode>& n) {
        return static_cast<double>(n->uptimeHours());
    });
    assert(avgUptime > 0.0);
    (void)avgUptime;

    // Сортування вузлів (std::sort з ЛР 2.1)
    container.sortNodesByName(true);
    for (size_t i = 1; i < container.nodes().size(); ++i) {
        assert(container.nodes()[i - 1]->name() <= container.nodes()[i]->name());
    }

    container.sortNodesByMetric(false); // За спаданням
    for (size_t i = 1; i < container.nodes().size(); ++i) {
        assert(container.nodes()[i - 1]->getPrimaryMetric() >= container.nodes()[i]->getPrimaryMetric());
    }

    // Додавання та видалення
    auto newNode = std::make_shared<ServerNode>(200, "temp-node", "10.10.10.10", "Test DC");
    container.addNode(newNode);
    assert(container.findNodeById(200) != nullptr);

    bool removed = container.removeNode(200);
    if (!removed) std::abort();
    assert(container.findNodeById(200) == nullptr);

    std::cout << "OK\n";
}

void testValidationAndExceptions() {
    std::cout << "[TEST] 5. Валідація даних та обробка винятків... ";

    // Порожня назва
    bool caughtEmptyName = false;
    try {
        ServerNode invalidNode(1, "", "10.0.0.1", "DC");
    } catch (const ValidationException&) {
        caughtEmptyName = true;
    }
    if (!caughtEmptyName) abort();

    // Некоректне навантаження CPU
    bool caughtInvalidCpu = false;
    try {
        ServerNode validNode(1, "node1", "10.0.0.1", "DC");
        validNode.setCpuUsage(150.0);
    } catch (const ValidationException&) {
        caughtInvalidCpu = true;
    }
    if (!caughtInvalidCpu) abort();

    // Дублювання IP-адреси
    InfrastructureContainer container;
    container.addNode(std::make_shared<ServerNode>(1, "node-a", "192.168.1.1", "DC"));
    bool caughtDup = false;
    try {
        container.addNode(std::make_shared<ServerNode>(2, "node-b", "192.168.1.1", "DC"));
    } catch (const DuplicateNodeException&) {
        caughtDup = true;
    }
    if (!caughtDup) abort();

    std::cout << "OK\n";
}

void testPersistenceAndExport() {
    std::cout << "[TEST] 6. Серіалізація в JSON та експорт ситуаційного звіту... ";

    InfrastructureContainer original;
    original.loadSampleInfrastructure();

    QString tempJson = "test_temp_infra.json";
    original.saveToFile(tempJson);

    InfrastructureContainer loaded;
    loaded.loadFromFile(tempJson);

    assert(loaded.totalNodes() == original.totalNodes());
    assert(loaded.incidents().size() == original.incidents().size());
    assert(loaded.findNodeById(101)->name() == original.findNodeById(101)->name());

    QString tempReport = "test_temp_report.txt";
    loaded.exportIncidentReport(tempReport);
    assert(QFile::exists(tempReport));

    QFile::remove(tempJson);
    QFile::remove(tempReport);

    std::cout << "OK\n";
}

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    std::cout << "======================================================\n";
    std::cout << "  МОДУЛЬНЕ ТЕСТУВАННЯ: CYBER FLEET MONITOR (ЛР 2.8)   \n";
    std::cout << "======================================================\n";

    testNodeHierarchy();
    testIncidentHierarchy();
    testStrategyPattern();
    testContainerOperations();
    testValidationAndExceptions();
    testPersistenceAndExport();

    std::cout << "======================================================\n";
    std::cout << "  УСІ ТЕСТИ ПРОЙДЕНО УСПІШНО! (6/6)                   \n";
    std::cout << "======================================================\n";
    return 0;
}
