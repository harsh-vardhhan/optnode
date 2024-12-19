import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QLineEdit, QFormLayout
)
import requests
import webbrowser
from urllib.parse import urlencode
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker

# SQLAlchemy setup
DATABASE_URL = "sqlite:///user_data.db"
Base = declarative_base()
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

# User model
class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, autoincrement=True)
    client_id = Column(String, nullable=True)
    api_secret = Column(String, nullable=True)
    redirect_url = Column(String, nullable=True)

# Create the user table if it doesn't exist
Base.metadata.create_all(engine)

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login Window")

        # Create a form layout for the fields
        form_layout = QFormLayout()

        # Add fields
        self.client_id = QLineEdit()
        self.api_secret = QLineEdit()
        self.redirect_url = QLineEdit()
        self.code = QLineEdit()
        self.access_token = QLineEdit()

        # Prefill fields from database
        self.prefill_fields()

        # Add widgets to the form layout
        form_layout.addRow("Client ID:", self.client_id)
        form_layout.addRow("API Secret:", self.api_secret)
        form_layout.addRow("Redirect URL:", self.redirect_url)

        # Add the Authorise button below the Redirect URL
        self.authorise_button = QPushButton("Authorise")
        self.authorise_button.clicked.connect(self.handle_authorise)  # Connect button click to handler
        form_layout.addRow(self.authorise_button)  # Add the button as a standalone row

        form_layout.addRow("Code:", self.code)

        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.handle_login)
        form_layout.addRow(self.login_button)

        form_layout.addRow("Access Token:", self.access_token)

        # Set layout for the LoginWindow
        self.setLayout(form_layout)

    def prefill_fields(self):
        user = session.query(User).first()
        if user:
            self.client_id.setText(user.client_id or "")
            self.api_secret.setText(user.api_secret or "")
            self.redirect_url.setText(user.redirect_url or "")

    def handle_authorise(self):
        url = "https://api.upstox.com/v2/login/authorization/dialog/"
        params = {
            "client_id": self.client_id.text(),
            "response_type": "code",
            "redirect_uri": self.redirect_url.text(),
        }
        # Encode parameters and append to the URL
        full_url = f"{url}?{urlencode(params)}"

        # Open the URL in the default web browser
        webbrowser.open(full_url, new=0, autoraise=True)

    def handle_login(self):
        url = 'https://api.upstox.com/v2/login/authorization/token'
        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        data = {
            'code': self.code.text(),
            'client_id': self.client_id.text(),
            'client_secret': self.api_secret.text(),
            'redirect_uri': self.redirect_url.text(),
            'grant_type': 'authorization_code',
        }
        response = requests.post(url, headers=headers, data=data)
        response_data = response.json()
        print(response_data)
        access_token = 'access_token'
        if access_token in response_data:
            self.access_token.setText(response_data[access_token])
            self.save_to_database()
        else:
            print('Reauthorise')

    def save_to_database(self):
        # Clear existing user data
        session.query(User).delete()

        # Save new user data
        new_user = User(
            client_id=self.client_id.text(),
            api_secret=self.api_secret.text(),
            redirect_url=self.redirect_url.text()
        )
        session.add(new_user)
        session.commit()
        print("User data saved to database.")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("No Code Algo Trading")

        # Create a "Login" button
        self.login_button = QPushButton("Login", self)
        self.login_button.clicked.connect(self.open_login_window)

        # Create a layout to stack the label and button
        layout = QVBoxLayout()
        layout.addWidget(self.login_button)

        # Create a central widget
        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def open_login_window(self):
        # Open the login window
        self.login_window = LoginWindow()
        self.login_window.resize(400, 300)
        self.login_window.show()

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.resize(400, 300)
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
