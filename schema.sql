create database if not exists real_estate;
use real_estate;

create table Agents (
    agent_id INT AUTO_INCREMENT primary key,
    name varchar(100) NOT NULL,
    email varchar(100),
    phone varchar(15)
);

create table Buyers (
    buyer_id INT AUTO_INCREMENT primary key,
    name varchar(100) NOT NULL,
    email varchar(100),
    phone varchar(15),
    budget decimal(10,2)
);

create table enquiries(
    enquiry_id INT AUTO_INCREMENT primary key,
    name varchar(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    phone VARCHAR(15),
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
);

create table Properties (
    property_id INT AUTO_INCREMENT primary key,
    address varchar(200) NOT NULL,
    city varchar(50),
    state varchar(50),
    zip_code varchar(10),
    price DECIMAL(10,2),
    bedrooms INT,
    bathrooms INT,
    sqft INT,
    listing_date DATE,
    agent_id INT,
    image_url varchar(255),
    foreign key (agent_id) REFERENCES Agents(agent_id)
);

create table Transactions (
    transaction_id INT AUTO_INCREMENT primary key,
    property_id INT,
    buyer_id INT,
    sale_price decimal(10,2),
    sale_date DATE,
    agent_id INT,
    foreign key (property_id) REFERENCES Properties(property_id),
    foreign key (buyer_id) REFERENCES Buyers(buyer_id),
    foreign key (agent_id) REFERENCES Agents(agent_id)

);
