DROP DATABASE IF EXISTS `nsrl`;

-- DROP TABLE IF EXISTS product;
-- DROP TABLE IF EXISTS os;
-- DROP TABLE IF EXISTS manufacturer;
-- DROP TABLE IF EXISTS file;

CREATE DATABASE IF NOT EXISTS `nsrl` CHARACTER SET latin1 COLLATE latin1_swedish_ci;
USE `nsrl`;

-- ----------------
-- Tables
-- ---------------

-- manufacturer details
CREATE TABLE IF NOT EXISTS `manufacturer` (
`code` varchar(50) NOT NULL,
`name` varchar(150) NOT NULL,
PRIMARY KEY (`code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- os details
CREATE TABLE IF NOT EXISTS `os` (
`system_code` VARCHAR(50) NOT NULL ,
`system_name` VARCHAR(150) NOT NULL ,
`system_version` VARCHAR(50) NOT NULL ,
`mfg_code` VARCHAR(50) NOT NULL ,
PRIMARY KEY (`system_code`) ,
INDEX `fk_os_mfg_code` (`mfg_code` ASC) ,
CONSTRAINT `os_fk_mfg`
FOREIGN KEY (`mfg_code` )
REFERENCES `nsrl`.`manufacturer` (`code` )
ON DELETE RESTRICT
ON UPDATE RESTRICT)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;

-- product details
CREATE TABLE IF NOT EXISTS `product` (
`product_code` INTEGER UNSIGNED NOT NULL ,
`product_name` VARCHAR(150) NOT NULL ,
`product_version` VARCHAR(49) NOT NULL ,
`mfg_code` VARCHAR(50) NOT NULL ,
`os_code` VARCHAR(50) NOT NULL,
`language` VARCHAR(256) NOT NULL ,
`application_type` VARCHAR(128) NOT NULL ,
PRIMARY KEY (`product_code`) ,
INDEX `product_mfg_code_index` (`mfg_code` ASC) ,
CONSTRAINT `product_fk_os`
FOREIGN KEY (`os_code` )
REFERENCES `nsrl`.`os` (`system_code` )
ON DELETE RESTRICT
ON UPDATE RESTRICT,
CONSTRAINT `product_fk_mfg`
FOREIGN KEY (`mfg_code` )
REFERENCES `nsrl`.`manufacturer` (`code` )
ON DELETE RESTRICT
ON UPDATE RESTRICT)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- file-hash details
CREATE TABLE IF NOT EXISTS `hash_file` (
`file_name` VARCHAR(256) NOT NULL ,
`file_size` BIGINT UNSIGNED NOT NULL ,
`product_code` INTEGER UNSIGNED NOT NULL ,
`op_system_code` VARCHAR(50) NOT NULL ,
`special_code` VARCHAR(20) NOT NULL ,
`hash_sha1` VARCHAR(40) NOT NULL ,
`hash_md5` VARCHAR(40) NOT NULL ,
`crc32` VARCHAR(8) NULL ,
`id` INTEGER UNSIGNED NOT NULL AUTO_INCREMENT ,
INDEX `file_index_product_code` (`product_code` ASC) ,
INDEX `file_index_op_system_code` (`op_system_code` ASC) ,
INDEX `file_index_special_code` (`special_code` ASC) ,
INDEX `file_index_hash_md5` (`hash_md5`) ,
INDEX `file_index_hash_sha1` (`hash_sha1`) ,
PRIMARY KEY (`id`) ,
CONSTRAINT `file_product_code`
FOREIGN KEY (`product_code` )
REFERENCES `nsrl`.`product` (`product_code` )
ON DELETE RESTRICT
ON UPDATE RESTRICT,
CONSTRAINT `file_op_code`
FOREIGN KEY (`op_system_code` )
REFERENCES `nsrl`.`os` (`system_code` )
ON DELETE RESTRICT
ON UPDATE RESTRICT)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;

-- ------------------------------
-- Procedures
-- -------------------------------

-- -------------------
-- NSRL_MFG_INSERT
-- -------------------
DELIMITER $$

DROP PROCEDURE IF EXISTS `NSRL_MFG_INSERT`$$
CREATE PROCEDURE `NSRL_MFG_INSERT`(IN a_mfg_code VARCHAR(100), IN a_mfg_name VARCHAR(100))
BEGIN

  DECLARE v_code VARCHAR(50) DEFAULT '';
 
  BEGIN
    DECLARE EXIT HANDLER FOR NOT FOUND
      BEGIN
       
        IF v_code = '' THEN
         
          INSERT INTO manufacturer(code,name)
          VALUES (a_mfg_code,a_mfg_name);
        END IF;
      END;

    SELECT code INTO v_code
    FROM manufacturer
    WHERE LOWER(code)= LOWER(a_mfg_code);

  END;

END$$

DELIMITER ;

-- ------------------
-- NSRL_OS_INSERT
-- -------------------
DELIMITER $$

DROP PROCEDURE IF EXISTS `NSRL_OS_INSERT`$$
CREATE PROCEDURE `NSRL_OS_INSERT`(IN a_system_code VARCHAR(50), IN a_system_name VARCHAR(150),
IN a_system_version VARCHAR(50), IN a_mfg_code VARCHAR(50))

BEGIN

  DECLARE v_system_code VARCHAR(50) DEFAULT '';
 
  BEGIN
    DECLARE EXIT HANDLER FOR NOT FOUND
      BEGIN
       
        IF v_system_code = '' THEN
         
          INSERT INTO os(system_code,system_name,system_version,mfg_code)
          VALUES (a_system_code,a_system_name,a_system_version,a_mfg_code);
        END IF;
      END;

    SELECT system_code INTO v_system_code
    FROM os
    WHERE LOWER(system_code)= LOWER(a_system_code);

  END;

END$$

DELIMITER ;

-- --------------------
-- NSRL_PRODUCT_INSERT
-- ---------------------
DELIMITER $$

DROP PROCEDURE IF EXISTS `NSRL_PRODUCT_INSERT`$$
CREATE PROCEDURE `NSRL_PRODUCT_INSERT`(IN a_product_code VARCHAR(50), IN a_product_name VARCHAR(150),
IN a_product_version VARCHAR(50), IN a_os_code VARCHAR(50), IN a_mfg_code VARCHAR(50),
IN a_language VARCHAR(256), IN a_application_type VARCHAR(128))

BEGIN

  DECLARE v_product_code INTEGER DEFAULT -1;
 
  BEGIN
    DECLARE EXIT HANDLER FOR NOT FOUND
      BEGIN
       
        IF v_product_code = -1 THEN
         
          INSERT INTO product (product_code,product_name,product_version,os_code,mfg_code,language,application_type)
          VALUES (a_product_code,a_product_name,a_product_version,a_os_code,a_mfg_code,a_language,a_application_type);
        END IF;
      END;

    SELECT product_code INTO v_product_code
    FROM product
    WHERE LOWER(product_code)= LOWER(a_product_code);

  END;

END$$

DELIMITER ;

-- ------------------------
-- NSRL_HASH_INSERT
-- ----------------------

DELIMITER $$

DROP PROCEDURE IF EXISTS `NSRL_HASH_INSERT`$$

CREATE PROCEDURE `NSRL_HASH_INSERT`(IN a_hash_sha1 VARCHAR(50), a_hash_md5 VARCHAR(40),
IN a_crc32 VARCHAR(8),IN a_file_name VARCHAR(256), IN a_file_size BIGINT, IN a_product_code INTEGER,
IN a_op_system_code VARCHAR(50), IN a_special_code VARCHAR(20))

BEGIN

  DECLARE v_Id INTEGER DEFAULT -1;
 
  BEGIN
    DECLARE EXIT HANDLER FOR NOT FOUND
      BEGIN
       
        IF v_Id = -1 THEN
         
          INSERT INTO hash_file (hash_sha1, hash_md5, crc32, file_name, file_size, product_code, op_system_code, special_code)
          VALUES (a_hash_sha1, a_hash_md5, a_crc32, a_file_name, a_file_size, a_product_code, a_op_system_code, a_special_code);
        END IF;
      END;

    SELECT id INTO v_Id
    FROM hash_file
    WHERE LOWER(hash_sha1) = LOWER(a_hash_sha1) AND LOWER(hash_md5) = LOWER(a_hash_md5) AND
    LOWER(op_system_code) = LOWER(a_op_system_code) AND LOWER(product_code) = LOWER(a_product_code) AND
    LOWER(file_name) = LOWER(a_file_name);

  END;

END$$

DELIMITER ;

COMMIT;


