# PhishGuard:

PhishGuard is a machine-learning powered URL risk score predictor system. It analyzes links and predicts whether the link is safe or malicious on a scale from 1 to 10, with 1 being safe and 10 being high risk. This project includes a training file with a dataset, an API built with Flask, and a simple deployment setup as well as files for a browser extension setup. 

## Features:
 - A machine learning training model using XGBoost
 - An API built using Flask
 - A browser extension for real-time phishing detection
 - Training dataset comprised of 600k URLs
 - Lightweight deployment using Gunicorn

## Requirements:
Ensure that python and the following packages are installed:
 - flask
 - flask-cors
 - xgboost
 - scikit-learn
 - pandas
 - numpy
 - joblib
 - gunicorn

All of these packages can be installed using pip or using the text file requirements.txt with the following command:
 - ```pip install -r requirements.txt ```

## Project Structure: 

``` phishguard/
│── extension/
|	└──|── icon.png
|	    |── manifest.json
|	    |── popup.html
|	    └── popup.js 
|── templates/
	└──── index.html 	
│── .DS_Store
│── .gitignore
│── Procfile
│── README.md
|── app.py
|── balanced_urls.csv
|── model_metadata.json
|── requirements.txt
|── strongest_phishing_model.pkl
└── train_model.py 
```

## Training the Model:
 1. Place the balanced_urls.csv in a place that the train_model.py can access and adapt the code at line 98 as necessary to ensure the program can access the file. 

 2. Run the train_model.py file either from a code editior or the command line using the following command:
 ```python train_model.py ```

## Running the Server:
 1. Start the Flask API using the file app.py either with a code editor or the following command:
   
    ```python app.py ```

 2.  Running the program should provide you with a link you can open in your browser to use the tool

## Browser Extension Setup:
 -  Load the extension
    1. Open either chrome or Firefox and go to extensions. Ensure developer mode is active

    2.  Select load unpacked and select the extension folder

## Contact:
 - Samikshya Bista and Ilana Minicozzi
 - Email: sbista02@rams.shepherd.edu or iminic01@rams.shepherd.edu
 - GitHub: https://github.com/samiphobic/Phishing_capstone 


