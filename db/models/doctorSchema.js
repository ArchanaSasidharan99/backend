import { Schema, model } from "mongoose";

const doctorSchema = Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    username: {
      type: String,
      required: true,
      trim: true,
      unique: true,
    },
    image: {
      type: String,
      required: true,
      trim: true,
    },
    specialization: {
      type: String,
      required: true,
      trim: true,
    },
    department: {
      type: Schema.Types.ObjectId,
      ref: "Department",
    },
    password: {
      type: String,
      required: true,
    },
  },
  { timestamps: true }
);

const Doctor = model("Doctor", doctorSchema);

export default Doctor;
