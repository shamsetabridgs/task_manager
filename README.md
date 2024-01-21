# QSL Problem_1

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)

## Requirements

- Python 3.12
- Django 5.0
- Postgres 16

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/shamsetabridgs/task_manager.git
    cd problem_1
    ```

2. Create a virtual environment:

    ```bash
    python -m venv venv
    ```

3. Activate the virtual environment:

    - For Windows:

        ```bash
        venv\Scripts\activate
        ```

    - For macOS/Linux:

        ```bash
        source venv/bin/activate
        ```

4. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

5. Apply migrations:

    ```bash
    python3 manage.py migrate
    ```

## Configuration

1. Configure Database

    ```env
    DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'task_manager',
        'USER': 'postgres',
        'PASSWORD': 'admin',
        'HOST': 'localhost',
        'PORT': '5432',
    }
   }
    ```

2. Update the `config/settings.py` file with your configuration.

## Usage

Run the development server:

```bash
python3 manage.py runserver
```

## API Endpoints

``` 
    Login: POST http://127.0.0.1:8000/user/login/
    Registration: POST http://127.0.0.1:8000/user/registration/
    Password-Reset: POST http://127.0.0.1:8000/user/reset-password/
    otp-verify: POST http://127.0.0.1:8000/user/otp-verify/
    Password-Set: POST http://127.0.0.1:8000/user/set-password/
    Task-Create: POST http://127.0.0.1:8000/user/tasks/
    Task-List: GET http://127.0.0.1:8000/user/tasks/
    Task-Details: GET http://127.0.0.1:8000/user/tasks/task_id/
    Task-Update: PUT http://127.0.0.1:8000/user/tasks/task_id/
    Task-Delete: DELETE http://127.0.0.1:8000/user/tasks/
    Task-Search: GET http://127.0.0.1:8000/user/task-search/
```