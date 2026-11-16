import { Component } from "react";

export default class Guard extends Component {
  constructor(props) {
    super(props);
    this.state = { failed: null, at: props.at };
  }

  static getDerivedStateFromError(error) {
    return { failed: String(error && error.message ? error.message : error) };
  }

  static getDerivedStateFromProps(props, state) {
    return props.at === state.at ? null : { failed: null, at: props.at };
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <div className="empty" role="alert">
        <h2>This page could not be shown</h2>
        <p className="muted">The rest of the console still works. Reload the page, or go back to the inventory.</p>
        <p className="mono small muted">{this.state.failed}</p>
      </div>
    );
  }
}
