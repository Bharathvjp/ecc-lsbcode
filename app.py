from flask import Flask, render_template, redirect, request, flash, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from steganography_tools import st
from gridfs import GridFS
import cv2
from pymongo import MongoClient
import binascii
import nacl.public
import os
from io import BytesIO
from PIL import Image 
import pymongo
import certifi

app = Flask(__name__)


app.secret_key = "hello"
app.config["IMAGE_UPLOADS"] = "static"
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ["JPEG", "JPG", "PNG"]

client=MongoClient('mongodb+srv://avinash:avinash@cluster0.to4vd.mongodb.net/ctf?retryWrites=true&w=majority', tlsCAFile= certifi.where())
db=client.ctf

def allowed_image(filename):
	if not "." in filename:
		return False
	ext = filename.rsplit(".", 1)[1]
	if ext.upper() in app.config["ALLOWED_IMAGE_EXTENSIONS"]:
		return True
	else:
		return False


@app.route("/")
def index():
	return render_template("index.html")

@app.route("/share/sharingbuttons")
def sharingbuttons():
	return render_template("sharingbuttons.php")



@app.route("/login", methods =['POST','GET'])
def login(): 
	if request.method == 'POST':
		login_user = db.users.find_one({"email": request.form['email']})

		if login_user:
			if check_password_hash(login_user['password'], request.form['password']):
				flash('Logged in successfully!', category='success')
				session['username'] = login_user['first_name'] 
				return redirect(url_for('home'))
			else:
				flash('Incorrect password, try again.', category='error')
		else:
			flash('Email does not exist.', category='error')
				
	return render_template("login.html")


@app.route("/signup", methods =['POST','GET'])
def signup():
	if request.method == 'POST':
		user_email = request.form['email']
		user_firstname = request.form['firstName']
		user_password1 = request.form['password1']
		user_password2 = request.form['password2']
			
		
		for users in db.users.find({},{"_id":0,"email":1}):
			if(user_email==users['email']):
				flash('Email already exists.', category='error')
				return redirect(url_for('signup'))
		if len(user_firstname) < 2:
			flash('First name must be greater than 1 character.', category='error')
		elif len(user_password1) < 7:
			flash('Password must be at least 7 characters.', category='error')	
		elif user_password1 != user_password2:
			flash('Passwords don\'t match.', category='error')
		else:
			Pkey = nacl.public.PrivateKey.generate()
			Pubkey = Pkey.public_key
			prikey = Pkey._private_key
			pubkey = Pubkey._public_key
			hashed_password = generate_password_hash(user_password1, method='sha256')
			db.users.insert_one({
    					'email':user_email,
    					'first_name': user_firstname,
    					'password':hashed_password,
    					'public_key':pubkey,
    					'private_key':prikey
						})
			return redirect('/login')
	return render_template("signup.html")

@app.route("/logout")
def logout():
	session.pop('username',None)
	return redirect(url_for("login"))



@app.route("/home")
def home():
	if 'username' in session:
		current_user = db.users.find_one({"first_name":session['username']})
		user_email = current_user['email']
		msgs = db.messages
		sort_msgs = msgs.find().sort('num', pymongo.DESCENDING)
		return render_template("home.html", user_email = user_email, msgs= sort_msgs)
		
	return redirect(url_for('login'))

@app.route("/home/msg", methods=['POST','GET'])	
def msg():
	if 'username' in session:
		if request.method == 'POST':
			current_user =	db.users.find_one({"first_name": session['username']})
			receiver_user = db.users.find_one({"email": request.form['email']})
			if receiver_user: #correct current user
				if request.form['email']==current_user['email']:
					flash("can't send to same username", category='error')
					return redirect(url_for("msg"))
				else:
					if len(request.form['plaintext'])<1:
						flash('Enter text greater than 1 character', category='error')
					else:	
						if request.files:
							image = request.files["image"]

							if allowed_image(image.filename):
								filename = secure_filename(image.filename)
								image.save(os.path.join(app.config["IMAGE_UPLOADS"], filename))

								oriimg = 'static/'+filename
								
								senders_private_key=current_user["private_key"]
								recp_pub_key=receiver_user["public_key"]
								senders_private_key_obj = nacl.public.PrivateKey(senders_private_key)
								recp_pub_key_obj = nacl.public.PublicKey(recp_pub_key)

								senders_box = nacl.public.Box(senders_private_key_obj, recp_pub_key_obj)
								shared_key=senders_box._shared_key
								message = request.form['plaintext']
								cipher = senders_box.encrypt(message.encode('utf-8'))
								x = binascii.hexlify(cipher)
								y = x.decode('utf-8')	
								img = os.path.join(app.config["IMAGE_UPLOADS"], filename)
								

								steg = st.LSBSteganography(cv2.imread(img))
								txt = y
								img_encoded = steg.encode_text(txt)
								cv2.imwrite("image_enc.png", img_encoded)

								fs = GridFS(db)
								
								filename = "image_enc.png"
								with open(filename, 'rb') as f:
									content = f.read()

								stored = fs.put(content, filename="stegoImage")	

								with open(oriimg, 'rb') as f:
									oricontent = f.read()

								oristored = fs.put(oricontent, filename='original Image')

								counter = db.counter.find_one({'counter':'count'})

								inbox_obj={
										 "num": counter["num"],
										"sender":current_user['email'],
										"recp":receiver_user['email'],
										"Image":stored,
										"oriimg": oristored
										}
								db.messages.insert_one(inbox_obj)
								if inbox_obj:
									db.counter.update_one({'counter':'count'},{"$inc":{'num':1}})


								flash("message sent", category='success')		
								return redirect(url_for("msg"))
							
							else:
								flash("Enter only Image", category='error')
								return redirect(url_for("msg"))
						else:
							flash("Enter an Image", category='error')
							return redirect(url_for("msg"))
			else:
				flash("Email does not exist", category='error')
				return redirect(url_for("msg"))
		return render_template("msg.html")	
	return redirect(url_for('login'))


@app.route("/home/decrpyt/<int:num>",methods=['POST','GET'])
def decrypt(num):
	if 'username' in session:
		user_email = session['username']
		message = db.messages.find_one({"num":num})
		image_id=message["Image"]

		fs = GridFS(db)
		outputdata =fs.get(image_id).read()

		scr = Image.open(BytesIO(outputdata))
		scr.save(r'image_got.png')
		scr.save(r'static/image_got.png')

		im = cv2.imread("image_got.png")
		steg = st.LSBSteganography(im)
		a = steg.decode_text()

		y1 = a.encode('utf-8')
		x1 = binascii.unhexlify(y1)

		message_enc=x1
		
		message_sender=message["sender"]
		message_reciever=message["recp"]
		
		sender_ob=db.users.find_one({"email":message_sender})
		sender_pub_key=sender_ob["public_key"]

		reciever_ob=db.users.find_one({"email":message_reciever})
		my_private_key=reciever_ob["private_key"] 

		reciever_private_key_obj = nacl.public.PrivateKey(my_private_key)
		sender_pub_key_obj = nacl.public.PublicKey(sender_pub_key)


		reciever_box = nacl.public.Box(reciever_private_key_obj, sender_pub_key_obj)

		plaintext = reciever_box.decrypt(message_enc)
		
		return render_template("decrypt.html", user_email= user_email, message= message, 
			plaintext = plaintext.decode('utf-8'),message_enc=y1)
		
	return redirect(url_for("login"))


@app.route("/home/decrpyt/compare/<int:num>", methods=['POST','GET'])
def compare(num):
	if 'username' in session:
		message = db.messages.find_one({"num":num})
		user_email = session['username']
		
		# img = message["oriimg"]
		# ori =  'static/'+ img
		#img = message["oriimg"]
		#ori =  'static/'+ img
		oriimage_id=message["oriimg"]
		fs = GridFS(db)
		oridata =fs.get(oriimage_id).read()
		oriscr = Image.open(BytesIO(oridata))
		oriscr.save(r'ori_image.png')

		ori = 'ori_image.png'

		#till here code
		original = cv2.imread(ori)
		cv2.imwrite("static/image_ori.jpg", original)
		
		print(ori)
		lsbEncoded = cv2.imread('image_got.png')
		
		original = cv2.cvtColor(original, cv2.COLOR_BGR2RGB)
		lsb_encoded_img = cv2.cvtColor(lsbEncoded, cv2.COLOR_BGR2RGB)
		compare_images = st.Compare(original, lsb_encoded_img)
		msr = compare_images.meanSquareError()
		conv_msr = float(msr)
		print(msr)
		psnr = compare_images.psnr()
		print(psnr)
		conv_psnr = float(psnr)
		
		return render_template("compare.html", user_email= user_email, msr=conv_msr, psnr=conv_psnr)

	return redirect(url_for("login"))

@app.route("/home/delete/<int:num>", methods=['POST','GET'])
def delete(num):
	if 'username' in session:
		msg = db.messages
		msg.delete_one({"num":num})
		flash("your message has been deleted",category='success')
		return redirect(url_for('home'))

	return redirect(url_for('login'))	




@app.route("/home/rasp")
def rasp():
	if 'username' in session:
		current_user = db.users.find_one({"first_name":session['username']})
		user_email = current_user['email']
		msgs = db.rmessages
		sort_msgs = msgs.find().sort('num', pymongo.DESCENDING)
		return render_template("rasp.html", user_email = user_email, msgs= sort_msgs)
		
	return redirect(url_for('login'))



@app.route("/home/rdecrpyt/<int:num>",methods=['POST','GET'])
def rdecrypt(num):
	if 'username' in session:
		user_email = session['username']
		message = db.rmessages.find_one({"num":num})
		image_id=message["Image"]

		fs = GridFS(db)
		outputdata =fs.get(image_id).read()

		scr = Image.open(BytesIO(outputdata))
		scr.save(r'image_got.png')
		scr.save(r'static/image_got.png')

		im = cv2.imread("image_got.png")
		steg = st.LSBSteganography(im)
		a = steg.decode_text()

		y1 = a.encode('utf-8')
		x1 = binascii.unhexlify(y1)

		message_enc=x1
		
		message_sender=message["sender"]
		message_reciever=message["recp"]
		
		sender_ob=db.users.find_one({"email":message_sender})
		sender_pub_key=sender_ob["public_key"]

		reciever_ob=db.users.find_one({"email":message_reciever})
		my_private_key=reciever_ob["private_key"] 

		reciever_private_key_obj = nacl.public.PrivateKey(my_private_key)
		sender_pub_key_obj = nacl.public.PublicKey(sender_pub_key)


		reciever_box = nacl.public.Box(reciever_private_key_obj, sender_pub_key_obj)

		plaintext = reciever_box.decrypt(message_enc)
		
		return render_template("decrypt.html", user_email= user_email, message= message, 
			plaintext = plaintext.decode('utf-8'),message_enc=y1)
		
	return redirect(url_for("login"))



@app.route("/home/rdelete/<int:num>", methods=['POST','GET'])
def rdelete(num):
	if 'username' in session:
		msg = db.rmessages
		msg.delete_one({"num":num})
		flash("your message has been deleted",category='success')
		return redirect(url_for('rasp'))

	return redirect(url_for('login'))



if __name__ == '__main__':
 	app.run(debug=True)



