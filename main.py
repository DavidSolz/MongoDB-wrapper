from secure_mongodb import SecureMongoDB
import os

if __name__ == "__main__":

    
    host = os.getenv('MONGODB_HOST', 'localhost')
    port = int(os.getenv('MONGODB_PORT', 27017))
    username = os.getenv('MONGODB_USERNAME', 'admin')
    password = os.getenv('MONGODB_PASSWORD', 'adminpassword')
    db_name = os.getenv('MONGODB_DB_NAME', 'data')

    CONNECTION_STRING = f"mongodb://{username}:{password}@{host}:{port}"

    try:

    ############################################

        # Create an instance of SecureMongoDB
        database = SecureMongoDB()

    ############################################


    ############################################

        # Open connection
        result = database.open_connection(db_name, CONNECTION_STRING)

    ############################################

    ############################################

        # Login
        result = database.login( 3, 'JohnSmith01!')

        if result['success'] is False:
            raise ValueError("Result is invalid")
        

    ############################################

    ############################################

        # Create user, this should be done only by user who belongs to sudo group
        result = database.add_user(4, 'Anna', 'Smith', 'JohnSmith01!', True)

    ############################################


    ############################################

        # Insert data to collection
        result = database.insert_data('some_data', ['Name','Lastname'], ['Hello', 'World'])
        result = database.insert_data('some_data', ['Name','Lastname'], ['Mark', 'World'])
        result = database.insert_data('some_data', ['Name','Lastname'], ['Anna', 'Smith'])

    ############################################


    ############################################
        # Get collection
        result = database.acquire_collection('some_data')

        if result['success'] is False:
            raise ValueError("Result is invalid")

        collection = result['data']

    ############################################




    ############################################

        # Print collection (collection is stored as list of dictionaries)
        print([collection['data'][i] for i in range(len(collection['data']))])

    ############################################




    ############################################
        # Modify collection

        # Find id of given item
        criteria = {'Name' : 'Hello'}
        result = database.find_value('some_data', criteria)

        if result['success'] is False:
            raise ValueError("Result is invalid")

        # Gather object id and print it to stdout
        item_id = result['data']['_id']

        # Modify single object with given id and update 
        result = database.modify_record('some_data', item_id, ['Lastname'], ['Brown'])

        # Modify multiple objects with given conditions
        criteria = {'Lastname' : 'World'}
        result = database.modify_records('some_data', criteria, ['Lastname'], ['Smith'])

        if result['success'] is False:
            raise ValueError("Result is invalid")

        # Get updated collection
        result = database.acquire_collection('some_data')

        if result['success'] is False:
            raise ValueError("Result is invalid")
        
        # Print result
        collection = result['data']

        print([collection['data'][i] for i in range(len(collection['data']))])

    #############################################


    ############################################

        # Delete collection
        result = database.drop_collection('some_data')

    ############################################


    ############################################

        # Logout
        result = database.logout()
        isConnected = result["success"]

    ############################################


    ############################################

        # Close the connection
        result = database.close_connection()

    ############################################

    except Exception as e:
        print(f"An error occurred: {e}")

