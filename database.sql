CREATE TABLE IF NOT EXISTS `users` (
	`username` VARCHAR(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
	`password` VARCHAR(64) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
	`uuid` VARCHAR(40) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
	`name` VARCHAR(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
	UNIQUE KEY `username_unique` (`username`) USING BTREE
) ENGINE=InnoDB;

