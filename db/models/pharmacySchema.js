import { Schema, model } from "mongoose";

const pharmacySchema = Schema({
  name: {
    type: String,
    required: true,
  },
  brand: {
    type: String,
    required: true,
  },
  price: {
    type: String,
    required: true,
  },
  quantity: {
    type: Number,
    required: true,
  },
  image: {
    type: String,
    required: true,
  },
  expiryDate: {
    type: Date,
    required: true,
  },
});

const Pharmacy = model("Pharmacy", pharmacySchema);

export default Pharmacy;
