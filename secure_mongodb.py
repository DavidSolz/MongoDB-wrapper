from pymongo import MongoClient #Version 3.11.0
from pymongo.errors import ServerSelectionTimeoutError
import os

import logging
from logging.handlers import TimedRotatingFileHandler

import hashlib
import secrets

class SecureMongoDB:

    

    def __init__(self, secure_connection=False, hash_iter=1000, backupCount = 5):

        """
            Initialize SecureMongoDB class.

            Args:
                secure_connection (bool, optional): If True, use SSL for the MongoDB connection. Default is False.
                hash_iter (int, optional): Number of iterations for password hashing using PBKDF2-HMAC-SHA512. Default is 1000.
                backupCount (int, optional): Number of log file backups to retain. Default is 5.
        """

        self.hash_iter = hash_iter
        self.db_name = os.getenv('MONGODB_DB_NAME', 'data')
        self.secure_connection = secure_connection
        self.user_id = -1

        # Configure logging
        log_dir = 'logs'
        os.makedirs(log_dir, exist_ok=True)

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)

        # Create a file handler and set the level to debug
        log_filename = os.path.join(log_dir, 'secure_mongodb.log')
        file_handler = TimedRotatingFileHandler(log_filename, when='midnight', interval=1, backupCount=backupCount)
        file_handler.setLevel(logging.DEBUG)

        # Create a console handler and set the level to info
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # Create a formatter and add it to the handlers
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        # Add the handlers to the logger
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def add_user(self, id, name :str, lastname :str, password :str, isAdmin :bool):

        """
            Create and insert a new user into the MongoDB 'users' collection.

            Args:
                id: Unique identifier for the new user.
                name (str): First name of the new user.
                lastname (str): Last name of the new user.
                password (str): Password for the new user.
                is_admin (bool): Boolean indicating if the new user has administrative privileges.

            Returns:
                dict: Dictionary with the success status and, if successful, the inserted user's ID.
        """

        try:

            if self.client.is_connected is False:
                raise ConnectionError("Invalid connection.")

            if self.user_id == -1:
                raise ValueError("User is not logged in. Operation requires authentication.")

            #Acquire users collection
            collection = self.db['users']

            # Check if the username already exists
            existing_user = collection.find_one({"id": id})

            if existing_user:
                raise ValueError(f"User with id {id} already exists.")

            # Generate salt and hash the password
            salt = secrets.token_bytes(16)
            hashed_password = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, self.hash_iter)

            # Insert the new user
            user_data = { "id": id, "name": name, "lastname": lastname, "salt": salt, "password": hashed_password, "privilages" : isAdmin}
            result = collection.insert_one(user_data)

            self.logger.info(f"User inserted: {result.inserted_id}")

            if isAdmin is True:
                self.insert_data('sudo_group', ['id'], [id])
                self.logger.info("User registered in sudo group")

            return {"success": True, "id": result.inserted_id}

        except Exception as e:
            self.logger.error(e)
            return {"success": False, "error_message": str(e)}

    

    def find_value(self, collection_name : str, criteria : dict):

        """
            Find a single value in a MongoDB collection based on specified criteria.

            Args:
                collection_name (str): Name of the MongoDB collection.
                criteria (dict): Dictionary specifying the search criteria.

            Returns:
                dict: Dictionary with the success status and, if successful, the found data.
        """

        try:

            if self.client.is_connected is False:
                raise ConnectionError("Invalid connection.")

            if self.user_id == -1:
                raise ValueError("User is not logged in. Operation requires authentication.")

            if collection_name in ['users']:
                self.logger.warning(f"Suspicious action takben by user {self.user_id}.")
                raise ConnectionError

            collection = self.db[collection_name]

            if collection is None:
                raise ValueError("Invalid value.")

            data = collection.find_one(criteria)
            
            return {"success": True, "data": data}
        except Exception as e:
            self.logger.error(e)
            return {"success": False, "error_message": str(e)}

    

    def find_values(self, collection_name: str, criteria: dict, limit : int = None, sort_by: str = None, sort_order: int = 1):
        
        """
            Find multiple values in a MongoDB collection based on specified criteria.

            Args:
                collection_name (str): Name of the MongoDB collection.
                criteria (dict): Dictionary specifying the search criteria.
                limit (int, optional): Maximum number of documents to return. Default is None (no limit).
                sort_by (str, optional): Field to sort the results by. Default is None (no sorting).
                sort_order (int, optional): Sorting order (1 for ascending, -1 for descending). Default is 1.

            Returns:
                dict: Dictionary with the success status and, if successful, the formatted collection data.
        """
        
        try:
            if self.client.is_connected is False:
                raise ConnectionError("Invalid connection.")

            if self.user_id == -1:
                raise ValueError("User is not logged in. Operation requires authentication.")

            collection = self.db[collection_name]

            if collection is None:
                raise ValueError("Invalid value.")

            data_cursor = collection.find(criteria).limit(limit) if limit is not None else collection.find(criteria)
            
            # Sort the data if sort_by is provided
            if sort_by is not None:

                # Use sort_order to determine the sorting order (1 for ascending, -1 for descending)
                data_cursor = data_cursor.sort(sort_by, sort_order)

            
            # Convert cursor to a list of dictionaries
            data = list(data_cursor)

            formatted_collection = {
                "name": collection_name,
                "data_count": len(data),
                "data" : data
            }

            return {"success": True, "data": formatted_collection}
        except Exception as e:
            self.logger.error(e)
            return {"success": False, "error_message": str(e)}

    
    
    def login(self, id, password : str):

        """
            Authenticate a user based on provided credentials.

            Args:
                id: User ID for authentication.
                password (str): Password for authentication.

            Returns:
                dict: Dictionary with the success status and, if successful, user information.
        """

        try:

            if self.client.is_connected is False:
                raise ConnectionError("Invalid connection.")

            collection = self.db['users']

            if collection is None:
                raise ValueError("Invalid value.")

            user_data = collection.find_one({'id' : id})

            if user_data is None or 'salt' not in user_data or 'password' not in user_data:
                raise ValueError("Invalid user data.")

            #Extract user salt
            salt = user_data['salt']

            #Extract user hash
            hash = user_data["password"]

            if hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, self.hash_iter) != hash:
                raise ValueError("Invalid credentials.")

            self.user_id = id
            self.logger.info(f"Logging in succesfull. Current user : {id}")

            return {"success": True, "firstname": user_data['name'], "lastname": user_data['lastname'], "admin": user_data['privilages']}

        except Exception as e:
            self.logger.error(e)
            return {"success": False, "error_message": str(e)}

    

    def logout(self):

        """
            Log out the currently logged-in user.

            Returns:
                dict: Dictionary with the success status and, if successful, a logout message.
        """

        try:
            if self.client.is_connected is False:
                raise ConnectionError("Invalid connection.")

            # Check if a user is currently logged in
            if self.user_id == -1:
                raise ValueError("No user is currently logged in.")

            # Log the user out
            self.logger.info(f"User {self.user_id} logged out successfully.")
            self.user_id = -1

            return {"success": True, "message": "User logged out successfully."}

        except Exception as e:
            self.logger.error(e)
            return {"success": False, "error_message": str(e)}


    
    def insert_data(self, collection_name : str, columns : list, values : list):
        
        """
            Insert data into a MongoDB collection.

            Args:
                collection_name (str): Name of the MongoDB collection.
                columns (list): List of column names for the data.
                values (list): List of corresponding values.

            Returns:
                dict: Dictionary with the success status and, if successful, the inserted data ID.
        """
        
        try:

            if self.client.is_connected is False:
                raise ConnectionError("Invalid connection.")

            if self.user_id == -1:
                raise ValueError("User is not logged in. Operation requires authentication.")

            #Acquire users collection
            collection = self.db[collection_name]

            # Construct a dictionary with column names and values
            data_to_insert = {column: value for column, value in zip(columns, values)}

            # Insert the data into the collection
            result = collection.insert_one(data_to_insert)

            self.logger.info(f"Data inserted: {result.inserted_id}")

            return {"success": True, "data_id": result.inserted_id}

        except Exception as e:
            self.logger.error(e)
            return {"success": False, "error_message": str(e)}
    
    def acquire_collection(self, collection_name : str):

        """
            Retrieve and format the data from a specified MongoDB collection.

            Args:
                collection_name (str): Name of the MongoDB collection.

            Returns:
                dict: Dictionary with the success status and, if successful, the formatted collection data.
        """

        try:

            if self.client.is_connected is False:
                raise ConnectionError("Invalid connection.")

            if self.user_id == -1:
                raise ValueError("User is not logged in. Operation requires authentication.")

            # Check if the collection name is 'users'
            if collection_name in ['users']:
                raise ValueError("Access to collection is restricted.")

            # Acquire the requested collection
            collection = self.db[collection_name]

            if collection is None:
                raise ValueError("Collection does not exist.")

            # Format and return the collection, data from collection is parsed as {name, number of rows, array of records}
            formatted_collection = {
                "name": collection_name,
                "data_count": collection.count_documents({}),
                "data" : list(collection.find())
            }

            return {"success": True, "data": formatted_collection}

        except Exception as e:
            self.logger.error(e)
            return {"success": False, "error_message": str(e)}

    def modify_record(self, collection_name : str, record_id, columns : list, values : list):

        """
            Modify a record in a MongoDB collection based on its ID.

            Args:
                collection_name (str): Name of the MongoDB collection.
                record_id: MongoDB ID of the record to modify.
                columns (list): List of column names to modify.
                values (list): List of corresponding values.

            Returns:
                dict: Dictionary with the success status and, if successful, a message indicating the modification.
        """

        try:

            if self.client.is_connected is False:
                raise ConnectionError("Invalid connection.")

            if self.user_id == -1:
                raise ValueError("User is not logged in. Operation requires authentication.")

            # Check if given user is sudo group
            result = self.find_value('sudo_group', {"id" : self.user_id})

            if result['data'] is None:
                self.logger.warning("Suspicious action taken by current user.")
                raise ValueError("User does not have proper rights.")

            # Acquire the specified collection
            collection = self.db[collection_name]

            if collection is None:
                raise ValueError("Invalid collection.")

            # Check if the record with the given ID exists
            existing_record = collection.find_one({"_id": record_id})

            if existing_record is None:
                raise ValueError(f"Record with ID '{record_id}' not found in collection '{collection_name}'.")

            # Create a dictionary of new values
            new_values = {column: value for column, value in zip(columns, values)}

            # Update the existing record with new values for specified fields
            updated_values = {field: value for field, value in new_values.items() if field in existing_record}
            collection.update_one({"_id": record_id}, {"$set": updated_values})

            self.logger.info(f"Record modified: {record_id}")
            return {"success": True, "message": f"Record with ID '{record_id}' successfully modified."}

        except Exception as e:
            self.logger.error(e)
            return {"success": False, "error_message": str(e)}

    def modify_records(self, collection_name : str, conditions : dict, columns : list, values : list):
        
        """
            Modify records in a MongoDB collection based on specified conditions.

            Args:
                collection_name (str): Name of the MongoDB collection.
                conditions (dict): Dictionary specifying conditions for selecting records to modify.
                columns (list): List of column names to modify.
                values (list): List of corresponding values.

            Returns:
                dict: Dictionary with the success status and, if successful, a message indicating the modification.
        """
        
        try:

            if self.client.is_connected is False:
                raise ConnectionError("Invalid connection.")

            if self.user_id == -1:
                raise ValueError("User is not logged in. Operation requires authentication.")

            # Acquire the specified collection
            collection = self.db[collection_name]

            if collection is None:
                raise ValueError("Invalid collection.")
            
            # Check if given user is sudo group
            result = self.find_value('sudo_group', {"id" : self.user_id})

            if result['data'] is None:
                self.logger.warning("Suspicious action taken by current user.")
                raise ValueError("User does not have proper rights.")

            # Find all records based on the specified conditions
            existing_records = list(collection.find(conditions))
            if len(existing_records) == 0:
                raise ValueError(f"No records found in collection '{collection_name}' based on the given conditions.")

            # Create a dictionary of new values
            new_values = {column: value for column, value in zip(columns, values)}

            # Update all existing records with new values for specified fields
            updated_values = {field: value for field, value in new_values.items() if field in existing_records[0]}
            collection.update_many(conditions, {"$set": updated_values})

            self.logger.info(f"Records modified based on conditions: {conditions}")

            return {"success": True, "data": "Records successfully modified based on given conditions."}

        except Exception as e:
            self.logger.error(e)
            return {"success": False, "error_message": str(e)}

    

    def drop_collection(self, collection_name : str):
        
        """
            Drop (delete) a MongoDB collection.

            Args:
                collection_name (str): Name of the MongoDB collection.

            Returns:
                dict: Dictionary with the success status and, if successful, None.
        """
        
        try:

            if self.client.is_connected is False:
                raise ConnectionError("Invalid connection.")

            if self.user_id == -1:
                raise ValueError("User is not logged in. Operation requires authentication.")

            # Acquire the specified collection
            collection = self.db[collection_name]

            # Check if given user is sudo group
            result = self.find_value('sudo_group', {"id" : self.user_id})

            if result['data'] is None:
                self.logger.warning("Suspicious action taken by current user.")
                raise ValueError("User does not have proper rights.")

            if collection is None:
                raise ValueError("Invalid collection.")

            collection.drop()

            self.logger.info(f"Collection dropped: {collection_name}")
            return {"success": True, "data": None}

        except Exception as e:
            self.logger.error(e)
            return {"success": False, "error_message": str(e)}

   
    def open_connection(self, db_name, url : str):

        """
            Open connection to the MongoDB database.

            Args:
                url (str): MongoDB connection string.

            Returns:
                dict: Dictionary with connection status and client information.
        """

        try:
            if self.secure_connection:
                url += "/?ssl=true"

            self.client = MongoClient(url, serverSelectionTimeoutMS=5000)

            # Check if the connection is successful by selecting the database
            self.client.server_info()

            self.db = self.client[db_name]
            self.logger.info("Connection to the database successful.")

            client_info = self.client._topology

            return {"success": True, "data": client_info}
        except ServerSelectionTimeoutError as e:
            self.logger.error(f"Unable to connect to the database. Check your connection settings. {e}")
            return {"success": False, "error_message": str(e)}

    def close_connection(self):
       
        """
            Close the connection to the MongoDB database.

            Returns:
                dict: Dictionary with the success status and, if successful, a message indicating the closure.
        """
       
        try:
            if self.client:
                self.client.close()
                self.logger.info("Connection to the database closed.")
                return {"success": True, "error_message": None}

        except Exception as e:
            self.logger.error(f"Error closing the database connection: {e}")
            return {"success": False, "error_message": str(e)}

if __name__ == "__main__":
    pass