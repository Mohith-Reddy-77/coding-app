from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import json
import requests
import os

app = Flask(__name__)
app.secret_key = 'f63fce843d2848c1b5b2df65ae89e2ce6cfe05f6b68a1b746c421d43a2f953c3'

JUDGE0_URL = "https://judge0-ce.p.rapidapi.com/submissions?base64_encoded=false&wait=true"
HEADERS = {
    "X-RapidAPI-Key": "6b1f477392mshbf5319075e63faep19d904jsn7d3ed169d188", 
    "X-RapidAPI-Host": "judge0-ce.p.rapidapi.com"
}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def load_users():
    with open("users.json", "r") as f:
        return json.load(f)

def save_users(users):
    with open("users.json", "w") as f:
        json.dump(users, f, indent=2)

def load_problems():
    file_path = os.path.join(os.path.dirname(__file__), 'problems.json')
    with open(file_path, 'r') as f:
        return json.load(f)
    
def load_submissions():
    with open("submissions.json", "r") as f:
        return json.load(f)

def save_submissions(data):
    with open("submissions.json", "w") as f:
        json.dump(data, f, indent=2)

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))

    problems = load_problems()
    submissions = load_submissions()
    user = session['user']
    user_data = submissions.get(user, {})

    for problem in problems:
        pid = str(problem['id'])
        sub_info = user_data.get(pid, {})
        problem['solved'] = sub_info.get('solved', False)
        problem['count'] = sub_info.get('count', 0)

    status_filter = request.args.get('status')  
    difficulty_filter = request.args.get('difficulty')  

    filtered_problems = problems

    if status_filter == 'solved':
        filtered_problems = [p for p in filtered_problems if p['solved']]
    elif status_filter == 'unsolved':
        filtered_problems = [p for p in filtered_problems if not p['solved']]

    if difficulty_filter:
        filtered_problems = [p for p in filtered_problems if p['difficulty'].lower() == difficulty_filter.lower()]

    return render_template('index.html',
                           problems=filtered_problems,
                           status_filter=status_filter or "all",
                           difficulty_filter=difficulty_filter or "")


@app.route('/problem/<int:id>')
@login_required
def problem(id):
    if 'user' not in session:
        flash("Please log in to access problems.", "warning")
        return redirect(url_for('login'))

    problems = load_problems()
    problem = next((p for p in problems if p['id'] == id), None)

    if not problem:
        return "Problem not found", 404

    return render_template('problem.html', problem=problem)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users = load_users()

        if any(u['username'] == username for u in users):
            return "Username already exists"

        hashed_pw = generate_password_hash(password)
        users.append({'username': username, 'password': hashed_pw})
        save_users(users)

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        session.pop('user', None)
        flash("You've been logged out for security. Please log in again.")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users = load_users()

        user = next((u for u in users if u['username'] == username), None)

        if not user:
            return redirect(url_for('register'))

        if check_password_hash(user['password'], password):
            session['user'] = username
            return redirect(url_for('dashboard'))

        return "Invalid password"

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    problems = load_problems()
    total = len(problems)

    submissions = load_submissions()
    user = session['user']
    user_data = submissions.get(user, {})

    solved = sum(1 for pid, info in user_data.items() if info.get("solved"))
    solved_titles = [p['title'] for p in problems if str(p['id']) in user_data and user_data[str(p['id'])].get("solved")]
    percent = int((solved / total) * 100) if total > 0 else 0

    return render_template('dashboard.html',
                           user=user,
                           solved=solved,
                           total=total,
                           percent=percent,
                           solved_titles=solved_titles) 


@app.route('/submit', methods=['POST'])
def submit():
    code = request.form['code']
    language_id = int(request.form['language'])
    problem_id = int(request.form['problem_id'])

    problems = load_problems()
    problem = next((p for p in problems if p['id'] == problem_id), None)

    results = []
    for case in problem['test_cases']:
        payload = {
            "source_code": code,
            "language_id": language_id,
            "stdin": case['input'],
            "expected_output": case['output']
        }

        response = requests.post(JUDGE0_URL, headers=HEADERS, json=payload)
        result = response.json()

        results.append({
            "input": case['input'],
            "expected_output": case['output'],
            "stdout": result.get('stdout', ''),
            "stderr": result.get('stderr', ''),
            "status": result.get('status', {}).get('description', 'Unknown')
        })
    passed = sum(1 for r in results if r["status"] == "Accepted")
    total = len(results)
    all_passed = (passed == total)

    user = session['user']
    submissions = load_submissions()

    if user not in submissions:
        submissions[user] = {}
    user_submissions = submissions[user]

    if str(problem_id) not in user_submissions:
        user_submissions[str(problem_id)] = {"solved": False, "count": 0}
    user_submissions[str(problem_id)]["count"] += 1
    if all_passed:
        user_submissions[str(problem_id)]["solved"] = True
    save_submissions(submissions)

    return render_template('result.html', results=results, title=problem['title'])

#if __name__ == '__main__':
    #app.run(debug=True)
