import { Schema, model } from "mongoose";

const slotSchema = Schema({
  doctor: {
    type: Schema.Types.ObjectId,
    ref: "Doctor",
  },
  startTime: {
    type: String,
  },
  endTime: {
    type: String,
  },
  availability: {
    type: Boolean,
    default: true,
  },
});

const Slot = model("Slot", slotSchema);

export default Slot;
