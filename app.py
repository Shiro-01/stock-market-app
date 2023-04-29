from distutils.util import execute
from genericpath import exists
from lib2to3.pygram import Symbols
import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)
# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# VIP   ------------------------------declaring global function to be used in jinja --------------------------------------------------------------------------------------------------------------->
app.jinja_env.globals['usd'] = usd
app.jinja_env.globals['lookup'] = lookup


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stocks = db.execute(
        "SELECT * from bought_stocks where user_id = ?", session["user_id"])
    cash = db.execute("SELECT cash FROM users WHERE id = ?",
                      session["user_id"])
    total = cash[0]["cash"]
    for stock in stocks:
        total += lookup(stock["symbol"])["price"]*stock["shares"]
    return render_template("index.html", stocks=stocks, cash=cash[0]["cash"], total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        stock = lookup(symbol)
        if not request.form.get("shares") or int(shares) < 0:
            return apology("the shares input is not a positive integer or empty.", 400)

        elif not request.form.get("symbol") or stock == None:
            return apology("the input is blank or the symbol does not exist.", 400)
        cash = db.execute(
            "SELECT cash FROM users WHERE id = ?", session["user_id"])

        # checking if there is tables count is  3 (1 of which is the user and the others are builtin with sqlite) then addd the new table of bought stocks
        tables_count = db.execute("SELECT count(*) FROM sqlite_master")
        print(tables_count)
        if tables_count[0]['count(*)'] == 3:
            db.execute("CREATE TABLE bought_stocks (stock_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, name TEXT NOT NULL, price NUMERIC NOT NULL, symbol TEXT NOT NULL, shares INTEGER NOT NULL, buying_date text, FOREIGN KEY (user_id) REFERENCES users(id))")
            db.execute("CREATE INDEX id_index ON users (id)")
            db.execute("CREATE INDEX user_id_index ON bought_stocks (user_id)")

        # buying the stock
        if cash[0]["cash"] > int(shares)*stock["price"]:
            # getting time
            # inserting stock into data base
            db.execute("INSERT INTO bought_stocks (user_id, name, price, symbol, shares, buying_date) VALUES (?, ?, ?, ?, ?, (SELECT datetime('now')))",
                       session["user_id"], stock["name"], stock["price"], stock["symbol"], int(shares))
            # updating user cash after purchase
            db.execute("UPDATE users SET cash = ? WHERE id = ?",
                       (cash[0]["cash"] - int(shares)*stock["price"]), session["user_id"])

            # adding the transation  to the logs
            db.execute("INSERT INTO logs (user_id, stock_symbol, price, shares, transaction_date, condition) VALUES (?, ?, ?, ?, (SELECT datetime('now')), 'Buy')",
                       session["user_id"], symbol.upper(), lookup(symbol)["price"], shares)

            return "purchases done"
        else:
            return apology("cannot afford the number of shares at the current price.", 400)
    elif request.method == "GET":
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    logs = db.execute(
        "SELECT * from logs where user_id = ? order by transaction_date DESC", session["user_id"])
    return render_template("history.html", logs=logs)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        stock = lookup(symbol)
        if stock == None:
            return apology("invalid stock symbol", 400)
        else:
            return render_template("quoted.html", stock=stock)



    elif request.method == "GET":
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not request.form.get("username"):
            return apology("user's input is blank or the username already exists", 400)

        elif not request.form.get("password") or not request.form.get("confirmation") or password != confirmation:
            return apology("input is blank or the passwords do not match", 400)
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                   username, generate_password_hash(password))
        except:
            return apology("username already exist", 400)
        return redirect("/login")
    elif request.method == "GET":
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "GET":
        Symbols = db.execute("SELECT DISTINCT(symbol) from bought_stocks where user_id = ?", session["user_id"])
        print(Symbols)
        return render_template("sell.html", Symbols=Symbols)

    elif request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # valdiating synbol
        if symbol == "choose stock symbol":
            return apology("the user fails to select a stock ", 400)

        # valditing the shares input
        else:
            shares_count = db.execute(
                "SELECT shares from bought_stocks where user_id = ? and symbol = ?", session["user_id"], symbol)[0]["shares"]

        if not request.form.get("shares") or int(shares) > int(shares_count) or int(shares) < 0:
            return apology("the user fails to select no of shares", 400)

        cash = db.execute("SELECT cash FROM users WHERE id=?",
                          session["user_id"])[0]["cash"]
        cash_update = cash + lookup(symbol)["price"] * float(shares)
        db.execute("UPDATE users SET cash = ? WHERE id = ?",
                   cash_update, session["user_id"])

        # regestring the log
        db.execute("INSERT INTO logs (user_id, stock_symbol, price, shares, transaction_date, condition) VALUES (?, ?, ?, ?, (SELECT datetime('now')), 'Sell')",
                   session["user_id"], symbol.upper(), lookup(symbol)["price"], shares)
        # updating the bought shares db
        if int(shares) == int(shares_count):
            db.execute("DELETE FROM bought_stocks WHERE symbol=?", symbol)
        else:
            db.execute("UPDATE bought_stocks SET shares = ? WHERE user_id = ? and symbol = ?", (int(shares_count) - int(shares)), session["user_id"], symbol)

        return "sell process complete"
