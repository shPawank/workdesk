from fastapi import FastAPI, Form, Request, Response, HTTPException, Depends
from pwdlib import PasswordHash
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
import secrets
from app.database import get_connection



hash_pass=PasswordHash.recommended()

app=FastAPI()
@app.get("/")
def home():
    return RedirectResponse(url="/login", status_code=303)

templates=Jinja2Templates(directory="templates")

# users=[]
sessions={}

@app.get("/register")
def register_page(request:Request):
    return templates.TemplateResponse(
        request=request,
        name="register.html"
    )

@app.get("/login")
def login_page(request:Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html"
    )



@app.post("/users")
def reg_user(
    username:str=Form(),
    full_name:str=Form(),
    email:str=Form(),
    password_hash:str=Form(),
):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        hashed_password = hash_pass.hash(password_hash)
        cursor.execute(
            "INSERT INTO users (username, full_name, email, password_hash) VALUES (%s, %s, %s, %s)",
            (username, full_name, email, hashed_password)
        )
        conn.commit()
    finally:
        cursor.close()
        conn.close()
        
    return RedirectResponse(
        url="/login",
        status_code=303
    )



@app.post("/users/login")
def login_user(
    username:str=Form(),
    password:str=Form(),
    response: Response = None
):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            select id, username, password_hash 
            from users
            where username=%s
            """,
            (username,)
            )
        user=cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    if not user:
        return{
            "message":"user not found"
        }

    user_id, username, password_hash = user
    if not hash_pass.verify(password, password_hash):
        return{
            "message":"invalid password"
        }

    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = user_id

    response = RedirectResponse(
        url="/dashboard",
        status_code=303
    )

    response.set_cookie(
        key="session_id",
        value=session_id
    )

    return response

def get_current_user(request: Request):
    session_id = request.cookies.get("session_id")
    user_id = sessions.get(session_id)

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="User no longer exists"
        )
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT id, username, full_name, email
            FROM users
            WHERE id = %s
            """,
            (user_id,)
        )

        user = cursor.fetchone()

    finally:
        cursor.close()
        conn.close()
    return user


@app.get("/profile")
def profile(
    request: Request,
    user=Depends(get_current_user)
):
    return templates.TemplateResponse(
        request=request,
        name="profile.html",
        context={
            "username": user[1],
            "full_name": user[2],
            "email": user[3]
        }
    )




@app.get("/dashboard")
def dashboard(
    request: Request,
    user=Depends(get_current_user)
):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        # 1. Count active notes belonging to this user
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM notes
            WHERE user_id = %s
              AND is_archived = FALSE
            """,
            (user[0],)
        )
        total_notes = cursor.fetchone()[0]

        # 2. Count saved links belonging to this user
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM saved_links
            WHERE user_id = %s
            """,
            (user[0],)
        )
        total_links = cursor.fetchone()[0]

        # 3. Fetch the five most recently updated active notes
        cursor.execute(
            """
            SELECT id, title, content, created_at
            FROM notes
            WHERE user_id = %s
              AND is_archived = FALSE
            ORDER BY updated_at DESC
            LIMIT 5
            """,
            (user[0],)
        )
        recent_notes = cursor.fetchall()

        # 4. Fetch the five most recently saved links
        cursor.execute(
            """
            SELECT id, title, url, created_at
            FROM saved_links
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 5
            """,
            (user[0],)
        )
        recent_links = cursor.fetchall()

    finally:
        cursor.close()
        conn.close()

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "username": user[1],
            "full_name": user[2],
            "total_notes": total_notes,
            "total_links": total_links,
            "recent_notes": recent_notes,
            "recent_links": recent_links
        }
    )



@app.get("/links")
def show_links(
    request: Request,
    user = Depends(get_current_user)
):  
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            select id, title, url, created_at
            from saved_links
            where user_id = %s
            order by created_at desc
            """,
            (user[0],)
        )
        links = cursor.fetchall()
    finally:
        cursor.close()
        conn.close()
    return templates.TemplateResponse(
        request=request,
        name="links.html",
        context={"links": links}
    )

@app.post("/links/{link_id}/delete")
def delete_link(
    link_id: int,
    user=Depends(get_current_user)
):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            DELETE FROM saved_links
            WHERE id = %s AND user_id = %s
            """,
            (link_id, user[0])
        )
        conn.commit()
    finally:
        cursor.close()
        conn.close()

    return RedirectResponse(
        url="/links",
        status_code=303
    )

@app.post("/links")
def save_link(
    title: str = Form(),
    url: str = Form(),
    user = Depends(get_current_user)
):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO saved_links (user_id, title, url)
            VALUES (%s, %s, %s)
            """,
            (user[0], title, url)
        )

        conn.commit()

    finally:
        cursor.close()
        conn.close()

    return RedirectResponse(
        url="/links",
        status_code=303
    )

@app.post("/notes")
def create_note(
    title: str = Form(),
    content: str = Form(),
    user=Depends(get_current_user)
):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO notes (user_id, title, content)
            VALUES (%s, %s, %s)
            """,
            (user[0], title, content)
        )
        conn.commit()

    finally:
        cursor.close()
        conn.close()

    return RedirectResponse(
        url="/notes",
        status_code=303
    )    
@app.get("/notes")
def show_notes(
    request: Request,
    user=Depends(get_current_user)
):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT id, title, content, created_at
            FROM notes
            WHERE user_id = %s
            AND is_archived = FALSE
            ORDER BY updated_at DESC
            """,
            (user[0],)
        )

        notes = cursor.fetchall()

    finally:
        cursor.close()
        conn.close()

    return templates.TemplateResponse(
        request=request,
        name="notes.html",
        context={"notes": notes}
    )

@app.post("/notes/{note_id}/update")
def update_note(
    note_id: int,
    title: str = Form(),
    content: str = Form(),
    user=Depends(get_current_user)
):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            UPDATE notes
            SET title = %s,
                content = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
              AND user_id = %s
              AND is_archived = FALSE
            """,
            (title, content, note_id, user[0])
        )
        conn.commit()

    finally:
        cursor.close()
        conn.close()

    return RedirectResponse(
        url="/notes",
        status_code=303
    )





@app.get("/logout")
def logout(request: Request):

    session_id=request.cookies.get("session_id")

    if session_id:
        sessions.pop(session_id, None)

    response = RedirectResponse(
        url="/login",
        status_code=303
    )
    response.delete_cookie("session_id")

    return response

@app.get("/profile")
def profile(user = Depends(get_current_user)):
    return {
        "username": user[1],
        "full_name": user[2],
        "email": user[3]
    }