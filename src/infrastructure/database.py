#!/usr/bin/env python3
"""
Configuración de base de datos MongoDB

Este módulo maneja la conexión y configuración de MongoDB.
"""

import logging
import os
from typing import Optional
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

logger = logging.getLogger(__name__)


class DatabaseConfig:
    """Configuración de la base de datos"""
    
    def __init__(self):
        self.connection_string = os.getenv(
            "MONGODB_CONNECTION_STRING", 
            "mongodb://localhost:27017"
        )
        self.database_name = os.getenv("MONGODB_DATABASE_NAME", "vulnerability_triage")
        self.connection_timeout = int(os.getenv("MONGODB_CONNECTION_TIMEOUT", "5000"))
        self.server_selection_timeout = int(os.getenv("MONGODB_SERVER_SELECTION_TIMEOUT", "5000"))
        self.max_pool_size = int(os.getenv("MONGODB_MAX_POOL_SIZE", "10"))
        self.min_pool_size = int(os.getenv("MONGODB_MIN_POOL_SIZE", "1"))


class DatabaseManager:
    """Gestor de conexiones a la base de datos"""
    
    def __init__(self, config: Optional[DatabaseConfig] = None):
        self.config = config or DatabaseConfig()
        self._client: Optional[MongoClient] = None
        self._database: Optional[Database] = None
    
    def connect(self) -> Database:
        """Establece conexión con MongoDB y retorna la base de datos"""
        if self._database is not None:
            return self._database
        
        try:
            logger.info(f"Connecting to MongoDB at {self.config.connection_string}")
            
            self._client = MongoClient(
                self.config.connection_string,
                connectTimeoutMS=self.config.connection_timeout,
                serverSelectionTimeoutMS=self.config.server_selection_timeout,
                maxPoolSize=self.config.max_pool_size,
                minPoolSize=self.config.min_pool_size,
                retryWrites=True,
                retryReads=True
            )
            
            # Verificar conexión
            self._client.admin.command('ping')
            
            self._database = self._client[self.config.database_name]
            
            logger.info(f"Successfully connected to MongoDB database: {self.config.database_name}")
            return self._database
            
        except ConnectionFailure as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise
        except ServerSelectionTimeoutError as e:
            logger.error(f"MongoDB server selection timeout: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error connecting to MongoDB: {e}")
            raise
    
    def disconnect(self):
        """Cierra la conexión con MongoDB"""
        if self._client:
            try:
                self._client.close()
                logger.info("Disconnected from MongoDB")
            except Exception as e:
                logger.error(f"Error disconnecting from MongoDB: {e}")
            finally:
                self._client = None
                self._database = None
    
    def get_database(self) -> Database:
        """Obtiene la instancia de la base de datos"""
        if self._database is None:
            return self.connect()
        return self._database
    
    def is_connected(self) -> bool:
        """Verifica si hay conexión activa con MongoDB"""
        if (self._client is None) or (self._database is None):
            return False
        
        try:
            self._client.admin.command('ping')
            return True
        except Exception:
            return False
    
    def create_collections_and_indexes(self):
        """Crea las colecciones y índices necesarios"""
        if self._database is None:
            raise RuntimeError("Database not connected")
        
        try:
            # Crear colecciones si no existen
            collections = [
                "vulnerabilities",
                "reports", 
                "analyses",
                "triage_results"
            ]
            
            existing_collections = self._database.list_collection_names()
            
            for collection_name in collections:
                if collection_name not in existing_collections:
                    self._database.create_collection(collection_name)
                    logger.info(f"Created collection: {collection_name}")
            
            # Los índices se crean automáticamente en cada repositorio
            logger.info("Database collections and indexes setup completed")
            
        except Exception as e:
            logger.error(f"Error creating collections and indexes: {e}")
            raise
    
    def drop_database(self):
        """Elimina completamente la base de datos (usar con precaución)"""
        if not self._client:
            raise RuntimeError("Database not connected")
        
        try:
            self._client.drop_database(self.config.database_name)
            logger.warning(f"Dropped database: {self.config.database_name}")
        except Exception as e:
            logger.error(f"Error dropping database: {e}")
            raise
    
    def get_database_stats(self) -> dict:
        """Obtiene estadísticas de la base de datos"""
        if not self._database:
            raise RuntimeError("Database not connected")
        
        try:
            stats = self._database.command("dbStats")
            return {
                "database_name": stats.get("db"),
                "collections": stats.get("collections"),
                "objects": stats.get("objects"),
                "data_size": stats.get("dataSize"),
                "storage_size": stats.get("storageSize"),
                "indexes": stats.get("indexes"),
                "index_size": stats.get("indexSize")
            }
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            return {}
    
    def __enter__(self):
        """Context manager entry"""
        return self.connect()
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()


# Instancia global del gestor de base de datos
_db_manager: Optional[DatabaseManager] = None


def get_database_manager() -> DatabaseManager:
    """Obtiene la instancia global del gestor de base de datos"""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager


def get_database() -> Database:
    """Obtiene la instancia de la base de datos"""
    return get_database_manager().get_database()


def close_database_connection():
    """Cierra la conexión global de la base de datos"""
    global _db_manager
    if _db_manager:
        _db_manager.disconnect()
        _db_manager = None