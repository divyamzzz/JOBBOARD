const fs=require('fs');
const multer=require('multer');
const {google}=require('googleapis');
const { file } = require('googleapis/build/src/apis/file');

const path="./job-board-ai-a73e8978ef3d.json";
const SCOPES=["https://www.googleapis.com/auth/drive"];

const auth=new google.auth.GoogleAuth({
    keyFile:path,
    scopes:SCOPES,
});

const drive=google.drive({version:"v3",auth});

async function uploadFileToDrive(filePath,fileName){
    try{
        const fileMetaData={
            name:fileName,
            parents:["17vAOFKWazGAuLeihi6Xvy8OaQzuE-7hu"],
        };
        const media={
            mimeType:"application/pdf",
            body:fs.createReadStream(filePath),
        };
        const response=await drive.files.create({
            resource:fileMetaData,
            media:media,
            fields:"id",
        });
        await drive.permissions.create({
            fileId:response.data.id,
            requestBody:{
                role:"reader",
                type:"anyone",
            },
        });
        return `https://drive.google.com/file/d/${response.data.id}/view`;
    }
    catch(error){
        console.error("Error uploading files",error);
        throw error
    }
}
module.exports={uploadFileToDrive};