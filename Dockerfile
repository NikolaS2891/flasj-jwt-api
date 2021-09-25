FROM python:3.8

WORKDIR /app

EXPOSE 5000
ENV FLASK_APP=app.py

COPY . /app
RUN python -m pip install --upgrade pip
RUN pip install -r requirements.txt

ENTRYPOINT [ "flask"]
CMD ["run", "-h", "0.0.0.0", "-p", "5000"]