# SecureMongoDB Class Documentation

The `SecureMongoDB` class is designed to provide a secure and flexible interface for interacting with a MongoDB database. It includes features for user authentication, data manipulation, and logging.

## Table of Contents
1. [Class Initialization](#class-initialization)
2. [User Management](#user-management)
3. [Data Manipulation](#data-manipulation)
4. [Connection Management](#connection-management)
5. [Logging](#logging)

## Class Initialization

### `__init__(self, secure_connection=False, hash_iter=1000, backupCount=5)`

Initialize the `SecureMongoDB` class.

- `secure_connection` (bool, optional): If True, use SSL for the MongoDB connection. Default is False.
- `hash_iter` (int, optional): Number of iterations for password hashing using PBKDF2-HMAC-SHA512. Default is 1000.
- `backupCount` (int, optional): Number of log file backups to retain. Default is 5.

## User Management

### `add_user(self, id, name: str, lastname: str, password: str, isAdmin: bool) -> dict`

Create and insert a new user into the MongoDB 'users' collection.

- `id`: Unique identifier for the new user.
- `name` (str): First name of the new user.
- `lastname` (str): Last name of the new user.
- `password` (str): Password for the new user.
- `isAdmin` (bool): Boolean indicating if the new user has administrative privileges.

Returns:
- `dict`: Dictionary with the success status and, if successful, the inserted user's ID.

### `login(self, id, password: str) -> dict`

Authenticate a user based on provided credentials.

- `id`: User ID for authentication.
- `password` (str): Password for authentication.

Returns:
- `dict`: Dictionary with the success status and, if successful, user information.

### `logout(self) -> dict`

Log out the currently logged-in user.

Returns:
- `dict`: Dictionary with the success status and, if successful, a logout message.

## Data Manipulation

### `insert_data(self, collection_name: str, columns: list, values: list) -> dict`

Insert data into a MongoDB collection.

- `collection_name` (str): Name of the MongoDB collection.
- `columns` (list): List of column names for the data.
- `values` (list): List of corresponding values.

Returns:
- `dict`: Dictionary with the success status and, if successful, the inserted data ID.

### `acquire_collection(self, collection_name: str) -> dict`

Retrieve and format the data from a specified MongoDB collection.

- `collection_name` (str): Name of the MongoDB collection.

Returns:
- `dict`: Dictionary with the success status and, if successful, the formatted collection data.

### `modify_record(self, collection_name: str, record_id, columns: list, values: list) -> dict`

Modify a record in a MongoDB collection based on its ID.

- `collection_name` (str): Name of the MongoDB collection.
- `record_id`: MongoDB ID of the record to modify.
- `columns` (list): List of column names to modify.
- `values` (list): List of corresponding values.

Returns:
- `dict`: Dictionary with the success status and, if successful, a message indicating the modification.

### `modify_records(self, collection_name: str, conditions: dict, columns: list, values: list) -> dict`

Modify records in a MongoDB collection based on specified conditions.

- `collection_name` (str): Name of the MongoDB collection.
- `conditions` (dict): Dictionary specifying conditions for selecting records to modify.
- `columns` (list): List of column names to modify.
- `values` (list): List of corresponding values.

Returns:
- `dict`: Dictionary with the success status and, if successful, a message indicating the modification.

### `drop_collection(self, collection_name: str) -> dict`

Drop (delete) a MongoDB collection.

- `collection_name` (str): Name of the MongoDB collection.

Returns:
- `dict`: Dictionary with the success status and, if successful, None.

## Connection Management

### `open_connection(self, url: str) -> dict`

Open connection to the MongoDB database.

- `url` (str): MongoDB connection string.

Returns:
- `dict`: Dictionary with connection status and client information.

### `close_connection(self) -> dict`

Close the connection to the MongoDB database.

Returns:
- `dict`: Dictionary with the success status and, if successful, a message indicating the closure.

## Logging

The `SecureMongoDB` class utilizes logging to record information about its operations. Log messages are stored in a rotating log file (`secure_mongodb.log`) and are also displayed on the console.

The log file is located in the 'logs' directory and is rotated daily, retaining up to 5 backup files.

Log Levels:
- DEBUG: Detailed information, typically useful for debugging.
- INFO: General information about system operation.
- WARNING: Warning messages, may indicate potential issues.
- ERROR: Error messages, indicating a problem that should be addressed.
- CRITICAL: Critical error messages, indicating a severe issue.

To configure logging, the class uses the `TimedRotatingFileHandler` to create log files with timestamps.

Log Format: `%(asctime)s - %(levelname)s - %(message)s`

