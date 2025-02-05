import React, { useState } from 'react';

interface ReportButtonProps {
  url: string;
  onReport: (url: string, description: string) => Promise<void>;
}

export const ReportButton: React.FC<ReportButtonProps> = ({ url, onReport }) => {
  const [isReporting, setIsReporting] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [description, setDescription] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsReporting(true);
    try {
      await onReport(url, description);
      setShowModal(false);
      setDescription('');
    } catch (error) {
      console.error('Failed to submit report:', error);
    } finally {
      setIsReporting(false);
    }
  };

  return (
    <>
      <button
        onClick={() => setShowModal(true)}
        className="px-4 py-2 text-sm bg-yellow-500 text-white rounded-lg hover:bg-yellow-600 transition-colors"
      >
        Report Phishing
      </button>

      {showModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-lg p-6 max-w-md w-full">
            <h3 className="text-lg font-bold mb-4">Report Suspicious URL</h3>
            <form onSubmit={handleSubmit}>
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  URL
                </label>
                <input
                  type="text"
                  value={url}
                  disabled
                  className="w-full p-2 border rounded-lg bg-gray-50"
                />
              </div>
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Description
                </label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="w-full p-2 border rounded-lg min-h-[100px]"
                  placeholder="Please describe why you think this URL is suspicious..."
                  required
                />
              </div>
              <div className="flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 text-gray-600 hover:text-gray-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isReporting}
                  className="px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 disabled:bg-gray-300"
                >
                  {isReporting ? 'Submitting...' : 'Submit Report'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}; 