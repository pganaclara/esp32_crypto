# Homomorphic Automaton on ESP32

An Arduino project that demonstrates a finite automaton simulated over encrypted data using the EC-ElGamal partially homomorphic encryption scheme. The entire simulation, including verification against clear-text results, runs on a single ESP32 microcontroller.

## Key Features

  * **Homomorphic Computation**: Performs state transitions and calculates enabled events on encrypted state vectors without decryption.
  * **Fully Generic Design**: Easily adaptable to different automata—including structure, rules, initial state, and event sequence—by changing a single configuration function.
  * **Built-in Verification**: Runs a parallel clear-text simulation at each step to verify the correctness of the homomorphic results.
  * **Cryptography**: Uses the Mbed TLS library (included with the ESP32 core) for `secp256r1` elliptic curve cryptography.
  * **Memory-Aware**: Includes careful memory management to run on the resource-constrained environment of a microcontroller.

## Requirements

### Hardware

  * An ESP32 Development Board (e.g., ESP32-DevKitC, NodeMCU-32S).

### Software

  * [Arduino IDE](https://www.arduino.cc/en/software) (version 1.8.19 or newer).
  * ESP32 Board Support Package installed in the Arduino IDE.
      * *Note: No external libraries are needed, as Mbed TLS is included with the ESP32 core.*

## Setup & Installation

1.  **Install Arduino & ESP32 Core**: Make sure you have the Arduino IDE installed and have added the ESP32 boards through the Board Manager.
2.  **Open the File**: Open the `.ino` project file in the Arduino IDE.
3.  **Configure IDE**: In the `Tools` menu, select your specific ESP32 board model and the correct COM port.
4.  **Upload**: Click the "Upload" button to compile and flash the code to your ESP32.
5.  **Monitor**: Open the Serial Monitor and set the baud rate to **115200**. The simulation will begin automatically.

## How It Works

The project is based on two core concepts:

### 1. Finite Automaton
The system is modeled as a finite automaton defined by:
* A set of **States**.
* A set of **Events** that trigger transitions.
* **Transition Rules (B-Matrices)**: Defines the next state (`new_state = B * current_state`).
* **Enabling Rules (R-Matrix)**: Defines which events are allowed to occur based on the current state (`enabled_events = R * current_state`).

### 2. Homomorphic Encryption
We use the **EC-ElGamal** scheme, which is additively homomorphic. This gives it a special property, often written as:
$E(m_1) \oplus E(m_2) = E(m_1 + m_2)$

Here’s what that means:
* **$E(m)$** is an encrypted value (a `Ciphertext`), which consists of two elliptic curve points.
* The **`⊕` operation** represents the homomorphic addition, which is performed by doing a component-wise addition of the points from the two ciphertexts.
* The result of this operation is a new, valid `Ciphertext` that is a correct encryption of the sum of the original messages ($m_1 + m_2$).

This property allows us to perform the matrix-vector multiplications (`B * state` and `R * state`) on the encrypted state vector by using a series of these homomorphic additions, all without ever decrypting the data.

## How to Customize the Automaton

This project is designed to be fully generic. **To define a completely new automaton and simulation run, you only need to edit the `define_automaton()` function.**

```c++
// The Single Point of Configuration
void define_automaton(AutomatonConfig& config) {
    // --- 1. Automaton Structure ---
    config.num_states = 6;
    config.num_events = 4;
    config.event_names = {"a1", "a2", "b1", "b2"};

    // --- 2. Automaton Rules ---
    // Transition Rules (B-Matrices): {from_state, to_state}
    config.transitions["a1"] = {{0, 1}, {5, 4}};
    config.transitions["a2"] = {{2, 5}};
    config.transitions["b1"] = {{4, 2}, {2, 4}};
    config.transitions["b2"] = {{4, 4}};

    // Enabling Rules (R-Matrix)
    // A '1' at R[event][state] means the event is enabled in that state.
    config.requirements = {
        //         s0 s1 s2 s3 s4 s5
        /* a1 */  {1, 0, 0, 0, 0, 1},
        /* a2 */  {0, 0, 1, 0, 0, 0},
        /* b1 */  {0, 1, 0, 0, 1, 0},
        /* b2 */  {0, 0, 1, 0, 1, 1}
    };

    // --- 3. Simulation Parameters ---
    // The initial state of the automaton.
    config.initial_state = {1, 0, 0, 0, 0, 0};
    
    // The sequence of events to run during the simulation.
    config.simulation_sequence = {"a1", "b1", "a2", "b2"};
}
```

## Example Output

When you run the code, you should see the following output in your Serial Monitor, with the results from the homomorphic and clear-text calculations matching at each step.

```
--- Starting Generic Automaton Simulation with Comparison ---
Automaton definition loaded.
Live matrices generated from definition.
Cryptography engine initialized successfully.

--- Starting Simulation ---

--- Step 1 (Event: a1) ---
Homomorphic Result -> New State: [0, 1, 0, 0, 0, 0], Enabled: [0, 0, 1, 0]
Clear-Text Result  -> New State: [0, 1, 0, 0, 0, 0], Enabled: [0, 0, 1, 0]
>>> Results Match! <<<

--- Step 2 (Event: b1) ---
Homomorphic Result -> New State: [0, 0, 0, 0, 1, 0], Enabled: [0, 0, 1, 1]
Clear-Text Result  -> New State: [0, 0, 0, 0, 1, 0], Enabled: [0, 0, 1, 1]
>>> Results Match! <<<

... and so on ...

--- Simulation Finished ---
>>> OVERALL RESULT: All steps matched successfully! <<<
```

-----

## \#\# License

This project is licensed under the MIT License.
