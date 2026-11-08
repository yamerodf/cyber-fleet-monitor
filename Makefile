BUILD_DIR = bin/build

.PHONY: all clean run test

all:
	@mkdir -p $(BUILD_DIR) bin
	@cmake -B $(BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=Release
	@cmake --build $(BUILD_DIR) -j$$(nproc)
	@cp -f $(BUILD_DIR)/cyber_monitor bin/
	@cp -f $(BUILD_DIR)/test_monitoring bin/
	@echo "Збірку успішно завершено: bin/cyber_monitor та bin/test_monitoring"

test: all
	@echo "Запуск автоматичних тестів..."
	@./bin/test_monitoring

run: all
	@./bin/cyber_monitor

clean:
	@rm -rf $(BUILD_DIR) bin/cyber_monitor bin/test_monitoring
	@echo "Очищення каталогу збірки завершено."
