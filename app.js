require("dotenv").config();
const express=require("express")
const bcrypt=require("bcrypt")
const bodyparser=require("body-parser")
const mongoose=require("mongoose");
const cors = require("cors");
const multer=require("multer");
const path=require("path");
const jwt=require("jsonwebtoken");
const fs=require("fs");
const pdfparse=require("pdf-parse");
const axios=require("axios");
const app=express();
app.use(cors());
app.use(express.json());  
app.use(bodyparser.urlencoded({ extended: true })); 
const { uploadFileToDrive } = require("./googledrive");
const {google}=require("googleapis");
const SCOPES=["https://www.googleapis.com/auth/drive"];



const credentials = {
    type: process.env.GOOGLE_TYPE,
    project_id: process.env.GOOGLE_PROJECT_ID,
    private_key_id: process.env.GOOGLE_PRIVATE_KEY_ID,
    private_key: process.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    client_email: process.env.GOOGLE_CLIENT_EMAIL,
    client_id: process.env.GOOGLE_CLIENT_ID,
    auth_uri: process.env.GOOGLE_AUTH_URI,
    token_uri: process.env.GOOGLE_TOKEN_URI,
    auth_provider_x509_cert_url: process.env.GOOGLE_AUTH_PROVIDER_X509_CERT_URL,
    client_x509_cert_url: process.env.GOOGLE_CLIENT_X509_CERT_URL,
    universe_domain: process.env.GOOGLE_UNIVERSE_DOMAIN
  };
  
  const googleAuthJSON = JSON.stringify(credentials);
  
  const { Storage } = require('@google-cloud/storage');
  
  const cloudStorage = new Storage({
    credentials: JSON.parse(googleAuthJSON)
  });
  const auth=new google.auth.GoogleAuth({
    credentials,
    scopes:SCOPES,
});
const drive=google.drive({version:"v3",auth});

app.use("/uploads/resumes",express.static(path.join(__dirname,"uploads/resumes")));
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("MongoDB Connected"))
  .catch((err) => console.error("MongoDB Connection Error:", err));

const userSchema = new mongoose.Schema({
    name: String,
    email: {type:String,unique:true},
    username: {type:String,unique:true},
    password: String,
    contact:String,
    phone:String,
    gender:String,
    resume:String,
    skills: [{ type: String }],
},{timestamps:true});

const User = mongoose.model("User", userSchema);

const storage=multer.diskStorage({
    destination:(req,file,cb)=>{
        cb(null,"uploads/resumes");
    },
    filename:(req,file,cb)=>{
       cb(null,`${Date.now()}-${file.originalname}`)
    }
})
const upload=multer({storage});

app.post("/api/auth/login", async (req, res) => {
try{
    const {email,password}=req.body;
    const user=await User.findOne({email});
    if(!user)
    {
        return res.status(400).json({success:false,message:"No user found"});
    }
    const isMatch=await bcrypt.compare(password,user.password);
    if(!isMatch)
    {
        return res.status(400).json({success:false,message:"No user found"});
    }
    const token=jwt.sign(
        {id:user._id},
        process.env.JWT_SECRET,
        {expiresIn:"1h"}
    );
    
        return res.status(200).json({success:true,message:"Login successfull",token});
}
catch(error)
{
    res.status(500).json({success:false,message:"server error"});
}
});
const authenticateToken=(req,res,next)=>{
    const token=req.header("Authorization");
    if(!token)
    {
        return res.status(401).json({success:false,message:"access denied"});
    }
    try{
        const verified=jwt.verify(token.split(" ")[1],process.env.JWT_SECRET);
        req.user=verified;
        next();
    }
    catch(error)
    {
        res.status(403).json({ success: false, message: "Invalid token" });
    }
}
app.get("/api/auth/me",authenticateToken,async(req,res)=>{
    try{
        const user=await User.findById(req.user.id).select("-password");
        if(!user)
        {
            return res.status(404).json({ success: false, message: "User not found" });
        }
        res.json({
            ...user._doc,
            resume: user.resume || null,
        });
    }
    catch(error)
    {
        res.status(500).json({ success: false, message: "Server error" });
    }
})
app.post("/api/auth/signup", upload.single("resume"),async(req,res)=>{
     try{
        const{name,username,email,password,contact,gender}=req.body;

        const exsistingEmail=await User.findOne({email});
        const exsistingUsername= await User.findOne({username});
        if(exsistingEmail)
        {
            return res.status(400).json({success:false,message:"Email already exsists"});
            
        }
        if(exsistingUsername)
        {
            return res.status(400).json({success:false,message:"Username already exsists"})
        }
        const saltRounds = parseInt(process.env.SALT);  
        const salt = await bcrypt.genSalt(saltRounds);
        const hashedpass=await bcrypt.hash(password,salt);

        let resumeURL=null;

        if(req.file)
        {
            resumeURL=await uploadFileToDrive(req.file.path,req.file.filename);
            fs.unlinkSync(req.file.path);
        }

        const newUser=new User({name,username,email,password:hashedpass,contact,gender,resume:resumeURL});
        await newUser.save();
        res.status(201).json({success:true,message:"New user created login now"});

     }
     catch(error)
     {
        console.error("Signup error",error);
        res.status(500).json({success:false,message:"server error"});
     }
})
app.get("/api/extract-skills/:userId", authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user || !user.resume) {
            return res.status(403).json({ success: false, message: "Resume not found" });
        }

        let fileId = user.resume; 

        
        const match = fileId.match(/[-\w]{25,}/); 
        if (match) {
            fileId = match[0]; 
        }

        if (!fileId) {
            return res.status(400).json({ success: false, message: "Invalid file ID" });
        }

        
        const fileMetadata = await drive.files.get({ fileId, fields: "mimeType" });
        if (fileMetadata.data.mimeType !== "application/pdf") {
            return res.status(400).json({ success: false, message: "Resume is not a PDF file" });
        }

        
        const response = await drive.files.get({ fileId, alt: "media" }, { responseType: "arraybuffer" });
        const pdfBuffer = Buffer.from(response.data);


        const pdfData = await pdfparse(pdfBuffer);
        const resumeText = pdfData.text.trim();
        if (!resumeText) {
            return res.status(400).json({ success: false, message: "Resume content is empty" });
        }

        
        const flaskURL = "https://flaskbackend-rw30.onrender.com/extract-skills";
        const flaskResponse = await axios.post(flaskURL, { resume_text: resumeText });

        if (!flaskResponse.data || !flaskResponse.data.skills) {
            return res.status(500).json({ success: false, message: "Invalid response from Flask server" });
        }

        
        const filteredSkills = flaskResponse.data.skills.map(skill => skill.trim()).filter(skill => skill.length > 1);
        await User.findByIdAndUpdate(req.params.userId, { skills: filteredSkills });

        return res.json({
            success: true,
            skills: filteredSkills
        });

    } catch (error) {
        console.error("Error extracting skills:", error);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
});



app.post("/api/get-jsearch-jobs/:userId", authenticateToken, async (req, res) => {
    try {
        const { skills } = req.body;
        if (!skills || skills.length === 0) {
            return res.status(400).json({ success: false, message: "No skills provided" });
        }
        const query = skills.join(",");
        const options = {
            method: 'GET',
            url: 'https://jsearch.p.rapidapi.com/search',
            params: {
                query: query,
                location: 'India',
                num_pages: '1'
            },
            headers: {
                'x-rapidapi-key': process.env.x_rapidapi_key,
                'x-rapidapi-host': process.env.x_rapidapi_host,
            }
        };

        const response = await axios.request(options);
        
        if (!response.data || !response.data.data) {
            return res.status(404).json({ success: false, message: "No jobs found" });
        }
        res.json({ success: true, jobs: response.data.data });

    } catch (error) {
        console.error("Error fetching jobs:", error);
        res.status(500).json({ success: false, message: "Server error", error: error.message });
    }
});

app.get("/api/check", (req, res) => {
    res.status(200).send("hello");
});



app.listen(5000, () => {
    console.log("Server started on port 5000");
});
