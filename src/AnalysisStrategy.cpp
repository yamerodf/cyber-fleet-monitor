#include "AnalysisStrategy.h"
#include "SpecificNodes.h"

// Реалізація порогового аналізу
std::vector<std::shared_ptr<SecurityIncident>> ThresholdAnalysisStrategy::analyze(
    const std::vector<std::shared_ptr<InfrastructureNode>>& nodes, int& nextIncidentId) {
    std::vector<std::shared_ptr<SecurityIncident>> found;

    for (const auto& node : nodes) {
        if (node->status() == NodeStatus::Offline) {
            continue;
        }

        // Перевірка на критичний рівень використання CPU
        if (node->cpuUsage() >= 90.0) {
            auto inc = std::make_shared<ResourceSpikeIncident>(
                nextIncidentId++, node->id(), node->name(), "127.0.0.1",
                IncidentSeverity::High,
                QString("Критичне навантаження на процесор вузла: %1%").arg(node->cpuUsage(), 0, 'f', 1),
                "CPU Usage", node->cpuUsage(), "high-load-worker-thread");
            found.push_back(inc);
        }

        // Перевірка на критичний рівень RAM
        if (node->ramUsage() >= 92.0) {
            auto inc = std::make_shared<ResourceSpikeIncident>(
                nextIncidentId++, node->id(), node->name(), "127.0.0.1",
                IncidentSeverity::Critical,
                QString("Вичерпання оперативної пам'яті: %1% (ризик OOM-Killer)").arg(node->ramUsage(), 0, 'f', 1),
                "RAM Usage", node->ramUsage(), "cache-buffer-leak");
            found.push_back(inc);
        }

        // Якщо це шлюз — перевіряємо відсоток втрати пакетів
        if (node->type() == NodeType::NetworkGateway) {
            auto gw = std::static_pointer_cast<NetworkGatewayNode>(node);
            if (gw->packetDropRate() >= 3.0) {
                auto inc = std::make_shared<DDoSAnomalyIncident>(
                    nextIncidentId++, gw->id(), gw->name(), "198.51.100.42",
                    IncidentSeverity::High,
                    QString("Аномальне падіння пакетів на шлюзі (%1%) при трафіку %2 Mbps")
                        .arg(gw->packetDropRate(), 0, 'f', 2).arg(gw->bandwidthMbps(), 0, 'f', 1),
                    gw->bandwidthMbps() / 100.0, 320.0, "UDP Flood Anomaly");
                found.push_back(inc);
            }
        }
    }
    return found;
}

// Реалізація евристичного аналізу аномалій
std::vector<std::shared_ptr<SecurityIncident>> HeuristicAnomalyStrategy::analyze(
    const std::vector<std::shared_ptr<InfrastructureNode>>& nodes, int& nextIncidentId) {
    std::vector<std::shared_ptr<SecurityIncident>> found;

    for (const auto& node : nodes) {
        // Якщо це сервер бази даних — перевірка співвідношення QPS та з'єднань
        if (node->type() == NodeType::DatabaseCluster) {
            auto db = std::static_pointer_cast<DatabaseNode>(node);
            if (db->queriesPerSecond() > 3000.0 && db->activeConnections() < 10) {
                auto inc = std::make_shared<UnauthorizedAccessIncident>(
                    nextIncidentId++, db->id(), db->name(), "203.0.113.88",
                    IncidentSeverity::Critical,
                    QString("Підозрілий сплеск SQL-запитів (%1 QPS) з єдиного неавторизованого пулу!")
                        .arg(db->queriesPerSecond(), 0, 'f', 0),
                    "Database Master Tables / Users & Hashes", 96);
                found.push_back(inc);
            }
        }

        // Якщо це сервер — перевірка нестандартного порту SSH або критичного диска
        if (node->type() == NodeType::GenericServer) {
            auto srv = std::static_pointer_cast<ServerNode>(node);
            if (srv->diskUsage() >= 95.0) {
                auto inc = std::make_shared<ResourceSpikeIncident>(
                    nextIncidentId++, srv->id(), srv->name(), "127.0.0.1",
                    IncidentSeverity::High,
                    QString("Дисковий простір майже вичерпано (%1%)! Ризик аварійної зупинки баз даних.")
                        .arg(srv->diskUsage(), 0, 'f', 1),
                    "Disk Space", srv->diskUsage(), "systemd-journald / log overflow");
                found.push_back(inc);
            }
        }
    }
    return found;
}
