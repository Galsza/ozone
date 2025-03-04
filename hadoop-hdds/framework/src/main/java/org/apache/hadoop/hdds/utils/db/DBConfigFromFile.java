/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.hdds.utils.db;

import static org.apache.hadoop.hdds.utils.HddsServerUtil.toIOException;
import static org.rocksdb.RocksDB.DEFAULT_COLUMN_FAMILY;

import com.google.common.base.Preconditions;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.apache.hadoop.hdds.StringUtils;
import org.apache.hadoop.hdds.utils.db.managed.ManagedColumnFamilyOptions;
import org.apache.hadoop.hdds.utils.db.managed.ManagedConfigOptions;
import org.apache.hadoop.hdds.utils.db.managed.ManagedDBOptions;
import org.eclipse.jetty.util.StringUtil;
import org.rocksdb.ColumnFamilyDescriptor;
import org.rocksdb.OptionsUtil;
import org.rocksdb.RocksDBException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A Class that controls the standard config options of RocksDB.
 * <p>
 * Important : Some of the functions in this file are magic functions designed
 * for the use of OZONE developers only. Due to that this information is
 * documented in this files only and is *not* intended for end user consumption.
 * Please do not use this information to tune your production environments.
 * Please remember the SpiderMan principal; with great power comes great
 * responsibility.
 */
public final class DBConfigFromFile {
  private static final Logger LOG =
      LoggerFactory.getLogger(DBConfigFromFile.class);

  public static final String CONFIG_DIR = "OZONE_CONF_DIR";

  private DBConfigFromFile() {
  }

  public static File getConfigLocation() throws IOException {
    String path = System.getenv(CONFIG_DIR);

    // Make testing easy.
    // If there is No Env. defined, let us try to read the JVM property
    if (StringUtil.isBlank(path)) {
      path = System.getProperty(CONFIG_DIR);
    }

    if (StringUtil.isBlank(path)) {
      LOG.debug("Unable to find the configuration directory. "
          + "Please make sure that " + CONFIG_DIR + " is setup correctly.");
      return null;
    }

    return new File(path);
  }

  /**
   * This class establishes a magic pattern where we look for DBFile.ini as the
   * options for RocksDB.
   *
   * @param dbFileName - The DBFile Name. For example, OzoneManager.db
   * @return Name of the DB File options
   */
  public static String getOptionsFileNameFromDB(String dbFileName) {
    Preconditions.checkNotNull(dbFileName);
    return dbFileName + ".ini";
  }

  /**
   * One of the Magic functions designed for the use of Ozone Developers *ONLY*.
   * This function takes the name of DB file and looks up the a .ini file that
   * follows the ROCKSDB config format and uses that file for DBOptions and
   * Column family Options. The Format for this file is specified by RockDB.
   * <p>
   * Here is a sample config from RocksDB sample Repo.
   * <p>
   * https://github.com/facebook/rocksdb/blob/master/examples
   * /rocksdb_option_file_example.ini
   * <p>
   * We look for a specific pattern, say OzoneManager.db will have its configs
   * specified in OzoneManager.db.ini. This option is used only by the
   * performance testing group to allow tuning of all parameters freely.
   * <p>
   * For the end users we offer a set of Predefined options that is easy to use
   * and the user does not need to become an expert in RockDB config.
   * <p>
   * This code assumes the .ini file is placed in the same directory as normal
   * config files. That is in $OZONE_DIR/etc/hadoop. For example, if we want to
   * control OzoneManager.db configs from a file, we need to create a file
   * called OzoneManager.db.ini and place that file in $OZONE_DIR/etc/hadoop.
   *
   * @param dbPath - The DB File Name, for example, OzoneManager.db.
   * @return DBOptions, Options to be used for opening/creating the DB.
   * @throws IOException
   */
  public static ManagedDBOptions readFromFile(Path dbPath) throws IOException {
    return readFromFile(dbPath, new ArrayList<>());
  }

  private static ManagedDBOptions readFromFile(Path dbPath, List<ColumnFamilyDescriptor> descriptors)
      throws IOException {
    Preconditions.checkNotNull(dbPath);

    //TODO: Add Documentation on how to support RocksDB Mem Env.
    ManagedDBOptions options = null;
    Path generatedDBPath = generateDBPath(dbPath);
    if (generatedDBPath.toFile().exists()) {
      options = new ManagedDBOptions();
      try {
        OptionsUtil.loadOptionsFromFile(new ManagedConfigOptions(), generatedDBPath.toString(),
            options, descriptors);

      } catch (RocksDBException rdEx) {
        throw toIOException("Unable to find/open Options file.", rdEx);
      }
    }
    return options;
  }

  public static ManagedColumnFamilyOptions readCFOptionsFromFile(Path dbPath, String cfName) throws IOException {
    List<ColumnFamilyDescriptor> descriptors = new ArrayList<>();
    String validatedCfName = StringUtil.isEmpty(cfName) ? StringUtils.bytes2String(DEFAULT_COLUMN_FAMILY) : cfName;
    readFromFile(dbPath, descriptors);
    Optional<ColumnFamilyDescriptor> cfDescriptor = descriptors.stream()
        .filter(descriptor -> StringUtils.bytes2String(descriptor.getName()).equals(validatedCfName))
        .findAny();
    if (!cfDescriptor.isPresent()) {
      LOG.debug("No columnFamilyDescriptor: {} present in file: {}", validatedCfName, dbPath);
      return null;
    }
    return new ManagedColumnFamilyOptions(cfDescriptor.get().getOptions());
  }

  /**
   * Tries looking up possible options for the DB. If the specified dbPath exists it uses it.
   * If not then it tries reading it from the default config location and also tries appending +.ini to the file.
   *
   * @param path
   * @return
   * @throws IOException
   */
  private static Path generateDBPath(Path path) throws IOException {
    if (path.toFile().exists()) {
      LOG.debug("RocksDB path found: {}, opening db from it.", path);
      return path;
    } else {
      LOG.debug("RocksDB path: {} not found, attempting to use fallback", path);
      File configLocation = getConfigLocation();
      if (configLocation != null &&
          StringUtil.isNotBlank(configLocation.toString())) {
        Path fallbackPath = Paths.get(configLocation.toString(),
            getOptionsFileNameFromDB(path.toString()));
        LOG.debug("Fallback path found: {}", path);
        return fallbackPath;
      }
    }
    LOG.error("No RocksDB path found");
    return Paths.get("");
  }

}
