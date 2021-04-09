import streamlit as st
import utils
import pickle
import sys


model = pickle.load(open("phishing_site_detector.sav", "rb"))

st.set_page_config(page_title="Phishing Website Detector")
st.title("Phishing Website Detector")

st.header("App that detects if the given url to a website is a legitimate or a phishing website")
st.subheader("Phishing is one of the major problems faced by cyber-world and leads to financial losses for both industries and individuals.Detection of phishing attack with high accuracy has always been a challenging issue. One of the effective way of checkingif a website/url is legitimate, or a scam is by checking its url. This detector uses an ML model to check if the given url is legitimate.")

st.text("")

user_input_url = st.text_input(label="Enter URL to check:")



if st.button("Predict"):

    is_http_present = user_input_url.find("http://",0,7)
    is_https_present = user_input_url.find("https://",0,8)

    if is_http_present != -1:
        user_input_url = user_input_url.replace("http://", "",1)

    if is_https_present != -1:
        user_input_url = user_input_url.replace("https://", "",1)

    print(is_http_present)
    print(is_https_present)
    print(user_input_url)

    with st.spinner("Predicting....."):
        prediction_df = utils.createPredictionDf(user_input_url)
        prediction = model.predict(prediction_df)

        if prediction == 1:
            st.success("This website is safe!")
            st.balloons()
        elif prediction == -1:
            st.error("This website is dangerous!")
