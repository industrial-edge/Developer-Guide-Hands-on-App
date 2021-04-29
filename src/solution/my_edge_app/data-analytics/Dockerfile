ARG BASE_IMAGE
FROM ${BASE_IMAGE}


# install all requirements from requirements.txt
COPY requirements.txt /
RUN pip install -r /requirements.txt; rm -f /requirements.txt


# Set the working directory to /app
WORKDIR /app
# Copy the current dir into the container at /app
COPY ./program/* /app/

# Run app.py when the container launches
CMD ["python", "-u", "-m", "app"]
