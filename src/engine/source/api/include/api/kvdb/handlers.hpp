#ifndef _API_KVDB_HANDLERS_HPP
#define _API_KVDB_HANDLERS_HPP

#include <memory>

#include <kvdb/kvdbManager.hpp>

#include <api/registry.hpp>

namespace api::kvdb::handlers
{

// New commands
api::Handler managerGet(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);
api::Handler managerPost(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);
api::Handler managerDelete(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);
api::Handler managerDump(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);

api::Handler dbGet(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);
api::Handler dbDelete(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);
api::Handler dbPut(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);

void registerHandlers(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager, std::shared_ptr<api::Registry> registry);
} // namespace api::kvdb::handlers

#endif // _API_KVDB_HANDLERS_HPP
