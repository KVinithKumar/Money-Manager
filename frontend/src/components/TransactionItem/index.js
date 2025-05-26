import { Component } from "react";
import { FaEdit, FaTrash, FaSave, FaTimes } from "react-icons/fa";
import "./index.css";

class TransactionItem extends Component {
  state = {
    isEditing: false,
    title: this.props.transactionDetails.title,
    amount: this.props.transactionDetails.amount,
    type: this.props.transactionDetails.type,
    error: "", // Add error state for validation
  };

  toggleEdit = () => {
    this.setState((prevState) => ({
      isEditing: !prevState.isEditing,
      title: this.props.transactionDetails.title,
      amount: this.props.transactionDetails.amount,
      type: this.props.transactionDetails.type,
      error: "", // Clear error on toggle
    }));
  };

  onChangeTitle = (event) => this.setState({ title: event.target.value });
  onChangeAmount = (event) => this.setState({ amount: event.target.value });
  onChangeType = (event) => this.setState({ type: event.target.value });

  saveTransaction = () => {
    const { transactionDetails, updateTransaction } = this.props;
    const { title, amount, type } = this.state;

    // Validate inputs
    if (!title.trim()) {
      this.setState({ error: "Title is required" });
      return;
    }
    if (!amount || isNaN(amount) || parseInt(amount) <= 0) {
      this.setState({ error: "Valid amount is required" });
      return;
    }

    const updatedTransaction = {
      title: title.trim(),
      amount: parseInt(amount),
      type,
    };

    console.log(
      `Saving transaction ID: ${transactionDetails.transactionId}`,
      updatedTransaction
    );
    updateTransaction(transactionDetails.transactionId, updatedTransaction);
    this.setState({ isEditing: false, error: "" });
  };

  deleteTransaction = () => {
    const { transactionDetails, deleteTransaction } = this.props;
    console.log(
      "Deleting transaction with ID:",
      transactionDetails.transactionId
    );
    deleteTransaction(transactionDetails.transactionId);
  };

  render() {
    const { transactionDetails, isNightMode } = this.props;
    const { isEditing, title, amount, type, error } = this.state;

    return (
      <li className={`transaction-item ${isNightMode ? "night-mode" : ""}`}>
        {isEditing ? (
          <>
            <input
              type="text"
              value={title}
              onChange={this.onChangeTitle}
              className="edit-field"
              placeholder="Enter title"
            />
            <input
              type="number"
              value={amount}
              onChange={this.onChangeAmount}
              className="edit-field"
              placeholder="Enter amount"
              min="1"
            />
            <select
              value={type}
              onChange={this.onChangeType}
              className="edit-field">
              <option value="Income">Income</option>
              <option value="Expenses">Expenses</option>
            </select>
            <span>
              {new Date(transactionDetails.date).toLocaleDateString()}
            </span>
            <div>
              <FaSave className="save-btn" onClick={this.saveTransaction} />
              <FaTimes className="cancel-btn" onClick={this.toggleEdit} />
            </div>
            {error && <p className="error-msg">{error}</p>}
          </>
        ) : (
          <>
            <span>{transactionDetails.title}</span>
            <span>{transactionDetails.amount}</span>
            <span>{transactionDetails.type}</span>
            <span>
              {new Date(transactionDetails.date).toLocaleDateString()}
            </span>
            <div>
              <FaEdit className="edit-btn" onClick={this.toggleEdit} />
              <FaTrash
                className="delete-btn"
                onClick={this.deleteTransaction}
              />
            </div>
          </>
        )}
      </li>
    );
  }
}

export default TransactionItem;
