# Convo - Frontend README

## Overview

Convo is a real-time chat application built with React and CSS, designed to provide a modern, responsive, and user-friendly messaging experience. The frontend integrates Google OAuth for secure authentication, Socket.IO for real-time communication, and a sleek UI with a pinkish-brown color scheme, interactive buttons, and a theme toggle feature.

## Features

- **Real-Time Messaging**: Enables users to send and receive messages instantly using Socket.IO.
- **Google Authentication**: Secure login and signup via Google OAuth.
- **Responsive Design**: Optimized for desktop and mobile devices with a sidebar for navigation and a clean chat interface.
- **Theme Toggle**: Switch between light and dark modes with sun/moon icons for enhanced user experience.
- **Interactive UI**: Includes profile modals, a search bar for finding contacts, and notification sounds for new messages.

## Tech Stack

- **React**: For building dynamic and reusable UI components.
- **CSS**: For responsive and customizable styling.
- **Socket.IO Client**: For real-time, bidirectional communication with the backend.
- **Axios**: For making HTTP requests to the backend API.
- **React Router**: For client-side routing and navigation.

## Prerequisites

- Node.js (v16 or higher)
- npm
- A running backend instance of Convo (see Backend README for setup)
- Google OAuth credentials configured for authentication

## Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/your-username/convo-frontend.git
   cd convo-frontend
   ```

2. **Install Dependencies**:

   ```bash
   npm install
   ```

3. **Set Up Environment Variables**: Create a `.env` file in the root directory and add the following:

   ```
   VITE_BACKEND_URL=http://localhost:5000
   VITE_GOOGLE_CLIENT_ID=your-google-client-id
   ```

   Replace `your-google-client-id` with your Google OAuth client ID.

4. **Run the Application**:

   ```bash
   npm run dev
   ```

## Usage

- **Login/Signup**: Use the Google authentication button to log in or sign up.
- **Chat Interface**: Select a contact from the sidebar to start a conversation.
- **Theme Toggle**: Click the sun/moon icon in the sidebar to switch themes.
- **Search Contacts**: Use the search bar to find users by name.

## Deployment

- Deploy the frontend on Vercel by connecting your GitHub repository.
- Ensure the backend URL in `.env` points to the deployed backend (e.g., Render).
- Update CORS settings in the backend to allow the deployed frontend URL.

## ![image](https://github.com/user-attachments/assets/9852735e-bff6-4d93-91e3-977bd17c35d8)


## ![image](https://github.com/user-attachments/assets/de694ecf-c1fd-47c3-a78a-be66b0eba4d7)


## ![image](https://github.com/user-attachments/assets/ba9a9fe7-6dee-467b-a6e4-b5552bd86c1b)

